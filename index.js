
var url = require('url'),
    crypto = require('crypto'),
    querystring = require('querystring'),
    scmp = require('scmp'),
    createError = require('http-errors');

/**
* Return a timestamp, optionally passing in extra seconds to add to the timestamp.
*
 * @param  {Number} ttl The extra seconds to add to the timestamp
 * @return {Number}     A timestamp in seconds
 */
function now (ttl) {

    if (ttl === undefined || ttl === null) {
        ttl = 0;
    }

    return Math.floor(new Date()/1000) + ttl;

}

/**
 * Create a HMAC digest based on a salt, a secret and a string.
 *
 * @param  {String} salt   The salt
 * @param  {String} secret The secret key
 * @param  {String} str    The string to included in the digest
 * @return {String}        A HMAC digest
 */
function createDigest (salt, secret, str) {

    // create the HMAC digest, using the URL path only
    return crypto
        .createHmac('sha256', secret)
        .update(`${salt}.${secret}.${str}`)
        .digest('base64');

}

/**
 * Given a modified (url.query has been manipulated) URL object (from url.parse())
 * return a string that matches what `url.path` would, but with correct values.
 *
 * @param  {Object} url An object as returned from `url.parse()` with a modified `query` property.
 * @return {String}     A string of the path (i.e. url.path + url.pathname)
 */
function urlPath (url) {

    // update the search, based on the query property
    url.search = querystring.stringify(url.query);

    // take into consideration empty search property when returning the string
    return url.pathname + (url.search ? `?${url.search}` : '');

}

/**
 * Given a modified (url.query has been manipulated) URL object (from url.parse())
 * return a string that mtaches what `url.path` would, but with correct values.
 *
 * @param  {Object} url An object as returned from `url.parse()` with a modified `query` property.
 * @return {String}     A string of the entire URL (including protocol, domain, pathname, path and search).
 */
function urlFormat (url) {

    url.search = querystring.stringify(url.query);

    return url.format();

}

/**
 * Verifies the URL being actioned by Express.
 *
 * @param  {String} path    The path of the URL
 * @param  {String} salt    The salt
 * @param  {String} secret  The secret key
 * @return {String|Boolean} true for valid, 'invalid' for 'invalid', 'timedout' if the request is too late
 */
function verifyUrl (path, salt, secret) {

    // recreate a digest from the URL path, minus the signature
    var parsedUrl = url.parse(path, true),
        parsedSignature = parsedUrl.query.signature,
        digest;

    // remove the signature as that isn't part of the signed string
    delete parsedUrl.query.signature;

    // recreate the digest
    digest = createDigest(salt, secret, urlPath(parsedUrl));

    // if we don't have the same value, we're unverified
    if (!scmp(digest, parsedSignature)) {
        return 'invalid';
    }

    parsedUrl.query.expires = parseInt(parsedUrl.query.expires) || 0;

    // verify if we're still within the expires timestamp
    return (now() < parsedUrl.query.expires) ? true : 'timedout';

}

/**
 * HMAC signed URLs middleware.
 *
 * This middleware adds a `req.signUrl()` function to sign a URL. This signed URL is validated
 * against the visitor's session.
 *
 * @param  {Object} options Configuration object.
 * @return {function}       Express middleware.
 */

module.exports = function hsu (options) {

    options = options || {};

    if (!options.secret) {
        throw Error('You must provide a secret for HSU to sign with.');
    }

    // get session options
    var sessionKey = options.sessionKey || 'session';

    // get ttl options (default to 1 hour)
    var ttl = parseInt(options.ttl) || 60*60;

    // return a function that will scope everything to an id (so we can use this middleware multiple times)
    return function (id) {

        if (!id) {
            throw Error('You must provide an id for HSU to scope with.');
        }

        return {

            setup: function hsuSetupMiddleware (req, res, next) {

                // lazy-load our signUrl function
                req.signUrl = function signUrl (urlToSign) {

                    // parse the URL we need to sign
                    var parsedUrl = url.parse(urlToSign, true),
                        salt = req[sessionKey][`hsu-${id}`],
                        expires = now(ttl);

                    // update the parsedUrl with the expries value before it is signed
                    // this protects us from tampering with the value
                    parsedUrl.query.expires = expires;

                    var digest = createDigest(salt, options.secret, urlPath(parsedUrl));

                    // store the salt in the session
                    req[sessionKey][`hsu-${id}`] = salt;

                    // now update the url with the information
                    parsedUrl.query.signature = digest;

                    // return the updated and signed URL
                    return urlFormat(parsedUrl);

                }

                return next();

            },

            verify: function hsuVerifyMiddleware (req, res, next) {

                // a salt should always exist, try and verify the request
                var verified = verifyUrl(req.originalUrl, req[sessionKey][`hsu-${id}`], options.secret);

                if (verified === 'invalid') {
                    throw createError(403, 'invalid HMAC digest', {
                        code: 'EBADHMACDIGEST'
                    });
                }

                if (verified === 'timedout') {
                    throw createError(403, 'URL has timed out', {
                        code: 'ETIMEOUTHMACDIGEST'
                    });
                }

                return next()

            },

            complete: function hsuCompleteMiddleware (req, res, next) {

                req.hsuComplete = function () {
                    delete req[sessionKey][`hsu-${id}`];
                }

                return next();

            }

        }

    }

}
