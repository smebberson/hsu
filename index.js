
var url = require('url'),
    crypto = require('crypto'),
    querystring = require('querystring'),
    scmp = require('scmp'),
    createError = require('http-errors'),
    rndm = require('rndm');

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
 * Verifies the URL being actioned by Express.
 *
 * @param  {String} path   The path of the URL
 * @param  {String} salt   The salt
 * @param  {String} secret The secret key
 * @return {Boolean}       true for valid, false for invalid
 */
function verifyUrl (path, salt, secret) {

    // recreate a digest from the URL path, minus the signature
    var parsedUrl = url.parse(path, true),
        parsedSignature = parsedUrl.query.signature,
        digest;

    // remove the signature as that isn't part of the signed string
    delete parsedUrl.query.signature;
    parsedUrl.search = querystring.stringify(parsedUrl.query);

    // recreate the digest
    digest = createDigest(salt, secret, parsedUrl.pathname + (parsedUrl.search ? `?${parsedUrl.search}` : ''));

    // verify the newly created digest matches the original
    return scmp(digest, parsedSignature);

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
                        salt = rndm(),
                        digest = createDigest(salt, options.secret, parsedUrl.path);

                    // store the salt in the session
                    req[sessionKey][`hsu-${id}`] = salt;

                    // now update the url with the information
                    parsedUrl.query.signature = digest;
                    parsedUrl.search = querystring.stringify(parsedUrl.query);

                    // return the updated and signed URL
                    return parsedUrl.format();

                }

                return next();

            },

            verify: function hsuVerifyMiddleware (req, res, next) {

                // a salt should always exist, try and verify the request
                var verified = verifyUrl(req.originalUrl, req[sessionKey][`hsu-${id}`], options.secret);

                if (!verified) {
                    throw createError(403, 'invalid HMAC digest', {
                        code: 'EBADHMACDIGEST'
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
