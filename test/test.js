
var url = require('url'),
    querystring = require('querystring'),
    express = require('express'),
    cookieSession = require('cookie-session'),
    request = require('supertest'),
    expect = require('chai').expect,
    hsu = require('../');

/**
 * Helper function to create an instance of an Express app.
 * @return {Object} The Express app.
 */
function createApp () {

    // create the express app
    var app = express()

    // we need a session
    app.use(cookieSession({ keys: ['A', 'B', 'C'] }));

    return app;

}



/**
 * Helper function to create a supertest agent for testing HSU against.
 * @return {TestAgent} A supertest agent configured against the Express app.
 */
function createAgent (app) {

    return request.agent(app);

}

describe('HSU', function () {

    // generate our HSU middleware
    var hsuProtect = hsu({
        secret: '%Y77JjYC9>d#,'
    });

    it('must be passed a secret', function () {

        var fn = function () {
            var middleware = hsu();
        }

        expect(fn).to.throw(Error);

    });

    describe('returns middleware that', function () {

        it('provides a signUrl function', function (done) {

            var app = createApp();

            app.get('/', function (req, res, next) {
                return res.send(typeof req.signUrl === 'function');
            });

            createAgent(app)
                .get('/')
                .expect(200, done);

        });

        describe('will sign a URL', function () {

            it('and store it in the users session', function (done) {

                var app = createApp(),
                    urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2';

                app.get('/', hsuProtect, function (req, res, next) {

                    // sign the url
                    req.signUrl(urlToSign);

                    // make sure req.session.hsuDigest exists
                    return res.send(Object.keys(req.session).indexOf('hsuSalt') >= 0);

                });

                // request to retrieve the signedUrl
                createAgent(app)
                    .get('/')
                    .expect(200, 'true', done);

            });

            it('and verify it', function (done) {

                var app = createApp(),
                    agent,
                    urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                    signedUrl;

                app.get('/account/reset', hsuProtect, function (req, res, next) {
                    signedUrl = req.signUrl(urlToSign);
                    res.status(200).end();
                });

                app.get('/reset', hsuProtect, function (req, res, next) {
                    res.status(200).end();
                });

                agent = createAgent(app);

                // request to retrieve the signedUrl
                agent
                    .get('/account/reset')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // now request the path of the signed url
                        agent
                            .get(url.parse(signedUrl, true).path)
                            .expect(200, done);

                    })

            });

            it('and 403 upon verification failure', function (done) {

                var app = createApp(),
                    agent,
                    urlToSign = 'https://domain.com/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                    signedUrl;

                app.get('/account/reset', hsuProtect, function (req, res, next) {

                    // let's tamper with the URL
                    var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                    tamperedUrl.query.user += '1';
                    tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                    signedUrl = tamperedUrl.format();

                    res.status(200).end();

                });

                app.get('/reset/fail', hsuProtect, function (req, res, next) {
                    res.status(200).end();
                });

                app.use(function (err, req, res, next) {

                    if (err.code !== 'EBADHMACDIGEST') {
                        return next(err);
                    }

                    res.status(403).end('URL has been tampered with');

                });

                agent = createAgent(app);

                // request to retrieve the signedUrl
                agent
                    .get('/account/reset')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // now request the path of the signed url
                        agent
                            .get(url.parse(signedUrl, true).path)
                            .expect(403, done);

                    })

            });

            it('will only support one HMAC digest at a time', function (done) {

                var app = createApp(),
                    agent,
                    urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                    signedUrl;

                app.get('/account/reset', hsuProtect, function (req, res, next) {

                    req.signUrl(urlToSign);
                    signedUrl = req.signUrl(urlToSign);
                    res.status(200).end();

                });

                app.get('/reset', hsuProtect, function (req, res, next) {
                    res.status(200).end();
                });

                agent = createAgent(app);

                // request to retrieve the signedUrl
                agent
                    .get('/account/reset')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // now request the path of the signed url
                        agent
                            .get(url.parse(signedUrl, true).path)
                            .expect(200, done);

                    })

            });

            it('and will 403 if a previously signed URL is used', function (done) {

                var app = createApp(),
                    agent,
                    urlToSign = 'https://domain.com/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                    signedUrl;

                app.get('/account/reset', hsuProtect, function (req, res, next) {

                    signedUrl = req.signUrl(urlToSign);
                    req.signUrl(urlToSign)

                    res.status(200).end();

                });

                app.get('/reset/fail', hsuProtect, function (req, res, next) {
                    res.status(200).end();
                });

                app.use(function (err, req, res, next) {

                    if (err.code !== 'EBADHMACDIGEST') {
                        return next(err);
                    }

                    res.status(403).end('URL has been tampered with');

                });

                agent = createAgent(app);

                // request to retrieve the signedUrl
                agent
                    .get('/account/reset')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // now request the path of the signed url
                        agent
                            .get(url.parse(signedUrl, true).path)
                            .expect(403, 'URL has been tampered with', done);

                    })

            });

            describe('without a domain', function () {

                it('and verify it', function (done) {

                    var app = createApp(),
                        agent,
                        urlToSign = '/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect, function (req, res, next) {
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect, function (req, res, next) {
                        res.status(200).end();
                    });

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                        .get('/account/reset')
                        .expect(200, function (err, res) {

                            if (err) {
                                return done(err);
                            }

                            // now request the path of the signed url
                            agent
                                .get(url.parse(signedUrl, true).path)
                                .expect(200, done);

                        })

                });

                it('and 403 upon verification failure', function (done) {

                    var app = createApp(),
                        agent,
                        urlToSign = '/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect, function (req, res, next) {

                        // let's tamper with the URL
                        var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                        tamperedUrl.query.user += '1';
                        tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                        signedUrl = tamperedUrl.format();

                        res.status(200).end();

                    });

                    app.get('/reset/fail', hsuProtect, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.use(function (err, req, res, next) {

                        if (err.code !== 'EBADHMACDIGEST') {
                            return next(err);
                        }

                        res.status(403).end('URL has been tampered with');

                    });

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                        .get('/account/reset')
                        .expect(200, function (err, res) {

                            if (err) {
                                return done(err);
                            }

                            // now request the path of the signed url
                            agent
                                .get(url.parse(signedUrl, true).path)
                                .expect(403, 'URL has been tampered with', done);

                        })

                });

            });

            describe('without a querystring', function () {

                it('and verify it', function (done) {

                    var app = createApp(),
                        agent,
                        urlToSign = '/reset',
                        signedUrl;

                    app.get('/account/reset', hsuProtect, function (req, res, next) {
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect, function (req, res, next) {
                        res.status(200).end();
                    });

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                        .get('/account/reset')
                        .expect(200, function (err, res) {

                            if (err) {
                                return done(err);
                            }

                            // now request the path of the signed url
                            agent
                                .get(url.parse(signedUrl, true).path)
                                .expect(200, done);

                        })

                });

                it('and 403 upon verification failure', function (done) {

                    var app = createApp(),
                        agent,
                        urlToSign = '/reset/fail',
                        signedUrl;

                    app.get('/account/reset', hsuProtect, function (req, res, next) {

                        // let's tamper with the URL
                        var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                        tamperedUrl.query.user += '1';
                        tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                        signedUrl = tamperedUrl.format();

                        res.status(200).end();

                    });

                    app.get('/reset/fail', hsuProtect, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.use(function (err, req, res, next) {

                        if (err.code !== 'EBADHMACDIGEST') {
                            return next(err);
                        }

                        res.status(403).end('URL has been tampered with');

                    });

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                        .get('/account/reset')
                        .expect(200, function (err, res) {

                            if (err) {
                                return done(err);
                            }

                            // now request the path of the signed url
                            agent
                                .get(url.parse(signedUrl, true).path)
                                .expect(403, 'URL has been tampered with', done);

                        })

                });

            });

        });

    });

});
