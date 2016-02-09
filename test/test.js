
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
