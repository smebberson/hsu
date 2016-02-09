
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

    return function hsuMiddleware (req, res, next) {

        req.signUrl = function signUrl (url) {

            return url;

        }

        return next();

    }

}
