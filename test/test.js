
var http = require('http'),
    express = require('express'),
    cookieSession = require('cookie-session'),
    request = require('supertest'),
    expect = require('chai').expect,
    hsu = require('../');

describe('HSU is middleware', function () {

    it('that provides a signUrl function', function (done) {

        var app = createApp();

        app.get('/', function (req, res, next) {
            return res.send(typeof req.signUrl === 'function');
        });

        request(createServer(app))
            .get('/')
            .expect(200, done);

    });

    it('will sign a URL for you', function (done) {

        var app = createApp(),
            urlToSign = 'https://www.google.com.au/webhp?sourceid=chrome-instant&ion=1&espv=2&ie=UTF-8#q=npm+hsu',
            signedUrl;

        app.get('/signed-url', function (req, res, next) {
            return res.send(req.signUrl(urlToSign));
        });

        request(createServer(app))
            .get('/signed-url')
            .expect(200, urlToSign, done);

    });

});

/**
 * Helper function to create an instance of an Express app.
 * @return {Object} The Express app.
 */
function createApp () {

    // create the connect app
    var app = express();

    // we need a session
    app.use(cookieSession({ keys: ['A', 'B', 'C'] }));

    // attach HSU
    app.use(hsu());

    return app;

}

/**
 * Helper function to create a server for testing HSU against.
 * @return {http.Server} The server to test URLs against
 */
function createServer (app) {

    app = app || createApp();

    return http.createServer(app);

}
