
var url = require('url'),
    querystring = require('querystring'),
    express = require('express'),
    cookieSession = require('cookie-session'),
    request = require('supertest'),
    expect = require('chai').expect,
    rndm = require('rndm'),
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
        }),
        tamperedErrorHandler = function (err, req, res, next) {

            if (err.code !== 'EBADHMACDIGEST') {
                return next(err);
            }

            res.status(403).end('URL has been tampered with');

        };

    it('must be passed a secret', function () {

        var fn = function () {
            var middleware = hsu();
        }

        expect(fn).to.throw(Error, /secret/);

    });

    describe('returns a scoping function that', function () {

        it('must be passed an id', function () {

            var fn = function () {
                var hsuProtect = hsu({ secret: 'secretvalue' })();
            };

            expect(fn).to.throw(Error, /id/);

        });

        it('returns three stages of middleware', function () {

            var id = rndm(),
                hsuProtect = hsu({ secret: 'secretvalue' });

            expect(hsuProtect(id)).to.have.property('setup');
            expect(hsuProtect(id)).to.have.property('verify');
            expect(hsuProtect(id)).to.have.property('complete');

        });

        it('allows multiple instances of HSU to run concurrently', function (done) {

            var idOne = rndm(),
                idTwo = rndm(),
                app = createApp(),
                agent,
                urlToSignOne = '/one?user=6dg3tct749fj&ion=1&espv=2',
                urlToSignTwo = '/two?user=6dg3tct749fj&ion=1&espv=2',
                signedUrlOne,
                signedUrlTwo;

                app.get('/pre/one', hsuProtect(idOne).setup, function (req, res, next) {
                    signedUrlOne = req.signUrl(urlToSignOne);
                    res.status(200).end();
                });

                app.get('/pre/two', hsuProtect(idTwo).setup, function (req, res, next) {
                    signedUrlTwo = req.signUrl(urlToSignTwo);
                    res.status(200).end();
                });

                app.get('/one', hsuProtect(idOne).verify, function (req, res, next) {
                    res.status(200).end();
                });

                app.get('/two', hsuProtect(idTwo).verify, function (req, res, next) {
                    res.status(200).end();
                });

                agent = createAgent(app);

                // request to retrieve signedUrlOne
                agent
                .get('/pre/one')
                .expect(200, function (err, res) {

                    if (err) {
                        return done(err);
                    }

                    // request to retrieve signedUrlTwo
                    agent
                    .get('/pre/two')
                    .expect(200, function (err, res) {

                        // now request signedUrlOne
                        agent
                        .get(url.parse(signedUrlTwo, true).path)
                        .expect(200, function (err, res) {

                            // now request signedUrlTwo
                            agent
                            .get(url.parse(signedUrlOne, true).path)
                            .expect(200, done);

                        });
                    });


                });

        });

        describe('returns middleware that', function () {

            it('provides a signUrl function', function (done) {

                var id = rndm(),
                    app = createApp();

                app.get('/', hsuProtect(id).setup, function (req, res, next) {
                    return res.status(200).send(Object.keys(req).indexOf('signUrl') >= 0 && typeof req.signUrl === 'function');
                });

                createAgent(app)
                .get('/')
                .expect(200, 'true', done);

            });

            describe('will sign a URL', function () {

                it('and store the salt in the users session', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2';

                    app.get('/', hsuProtect(id).setup, function (req, res, next) {

                        // sign the url
                        req.signUrl(urlToSign);

                        // make sure req.session.hsuDigest exists
                        return res.send(Object.keys(req.session).indexOf(`hsu-${id}`) >= 0);

                    });

                    // request to retrieve the signedUrl
                    createAgent(app)
                    .get('/')
                    .expect(200, 'true', done);

                });

                it('and remove the salt once complete', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/', hsuProtect(id).setup, function (req, res, next) {

                        // sign the url
                        signedUrl = req.signUrl(urlToSign);

                        // make sure req.session.hsuDigest exists
                        return res.send(Object.keys(req.session).indexOf(`hsu-${id}`) >= 0);

                    });

                    app.get('/reset', hsuProtect(id).verify, hsuProtect(id).complete, function (req, res, next) {
                        // we're done with this HSU
                        req.hsuComplete();
                        // the req.session.hsuDigest value should no longer exist
                        return res.send(Object.keys(req.session).indexOf(`hsu-${id}`) >= 0);
                    });

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                    .get('/')
                    .expect(200, 'true', function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // complete the process
                        agent
                        .get(url.parse(signedUrl, true).path)
                        .expect(200, 'false', done);

                    });

                });

                it('will protect the URL', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/reset/account', hsuProtect(id).setup, function (req, res, next) {
                        // retrieve the signed URL
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.use(tamperedErrorHandler);

                    // request to retrieve the signedUrl
                    createAgent(app)
                    .get('/reset/account')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // try the signed URL on another agent (simulating a new client), it should error
                        createAgent(app)
                        .get(url.parse(signedUrl, true).path)
                        .expect(403, done);

                    });

                });

                it('and verify it', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
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

                    });

                });

                it('and 403 upon verification failure', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {

                        // let's tamper with the URL
                        var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                        tamperedUrl.query.user += '1';
                        tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                        signedUrl = tamperedUrl.format();

                        res.status(200).end();

                    });

                    app.get('/reset/fail', hsuProtect(id).verify, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.use(tamperedErrorHandler);

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

                it('will only support one HMAC digest per ID at a time', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {

                        req.signUrl(urlToSign);
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();

                    });

                    app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
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

                it('and will allow the process to repeat', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/reset/account', hsuProtect(id).setup, function (req, res, next) {
                        // retrieve the signed URL
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.get('/complete', hsuProtect(id).complete, function (req, res, next) {
                        // we're done with this HSU
                        req.hsuComplete();
                        res.status(200).end();
                    })

                    app.use(tamperedErrorHandler);

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                    .get('/reset/account')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // verify the url
                        agent
                        .get(url.parse(signedUrl, true).path)
                        .expect(200, function (err, res) {

                            // complete the process
                            agent
                            .get('/complete')
                            .expect(200, function (err, res) {

                                if (err) {
                                    return done(err);
                                }

                                // start the process again, retrieve the signedUrl
                                // request to retrieve the signedUrl
                                agent
                                .get('/reset/account')
                                .expect(200, function (err, res) {

                                    if (err) {
                                        return done(err);
                                    }

                                    // verify the url
                                    agent
                                    .get(url.parse(signedUrl, true).path)
                                    .expect(200, done);

                                });

                            });


                        });

                    });

                });

                it('and will 403 if request repeated after completion', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/reset/account', hsuProtect(id).setup, function (req, res, next) {
                        // retrieve the signed URL
                        signedUrl = req.signUrl(urlToSign);
                        res.status(200).end();
                    });

                    app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.get('/complete', hsuProtect(id).complete, function (req, res, next) {
                        // we're done with this HSU
                        req.hsuComplete();
                        res.status(200).end();
                    });

                    app.use(tamperedErrorHandler);

                    agent = createAgent(app);

                    // request to retrieve the signedUrl
                    agent
                    .get('/reset/account')
                    .expect(200, function (err, res) {

                        if (err) {
                            return done(err);
                        }

                        // verify the url
                        agent
                        .get(url.parse(signedUrl, true).path)
                        .expect(200, function (err, res) {

                            // complete the process
                            agent
                            .get('/complete')
                            .expect(200, function (err, res) {

                                if (err) {
                                    return done(err);
                                }

                                // try and verify the URL again, it should error
                                agent
                                .get(url.parse(signedUrl, true).path)
                                .expect(403, done);

                            })


                        });

                    });

                });

                it('and will 403 if a previously signed URL is used', function (done) {

                    var id = rndm(),
                        app = createApp(),
                        agent,
                        urlToSign = 'https://domain.com/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                        signedUrl;

                    app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {

                        signedUrl = req.signUrl(urlToSign);
                        req.signUrl(urlToSign)

                        res.status(200).end();

                    });

                    app.get('/reset/fail', hsuProtect(id).verify, function (req, res, next) {
                        res.status(200).end();
                    });

                    app.use(tamperedErrorHandler);

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

                        var id = rndm(),
                            app = createApp(),
                            agent,
                            urlToSign = '/reset?user=6dg3tct749fj&ion=1&espv=2',
                            signedUrl;

                        app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {
                            signedUrl = req.signUrl(urlToSign);
                            res.status(200).end();
                        });

                        app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
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

                        var id = rndm(),
                            app = createApp(),
                            agent,
                            urlToSign = '/reset/fail?user=6dg3tct749fj&ion=1&espv=2',
                            signedUrl;

                        app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {

                            // let's tamper with the URL
                            var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                            tamperedUrl.query.user += '1';
                            tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                            signedUrl = tamperedUrl.format();

                            res.status(200).end();

                        });

                        app.get('/reset/fail', hsuProtect(id).verify, function (req, res, next) {
                            res.status(200).end();
                        });

                        app.use(tamperedErrorHandler);

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

                        var id = rndm(),
                            app = createApp(),
                            agent,
                            urlToSign = '/reset',
                            signedUrl;

                        app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {
                            signedUrl = req.signUrl(urlToSign);
                            res.status(200).end();
                        });

                        app.get('/reset', hsuProtect(id).verify, function (req, res, next) {
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

                        var id = rndm(),
                            app = createApp(),
                            agent,
                            urlToSign = '/reset/fail',
                            signedUrl;

                        app.get('/account/reset', hsuProtect(id).setup, function (req, res, next) {

                            // let's tamper with the URL
                            var tamperedUrl = url.parse(req.signUrl(urlToSign), true);

                            tamperedUrl.query.user += '1';
                            tamperedUrl.search = querystring.stringify(tamperedUrl.query);

                            signedUrl = tamperedUrl.format();

                            res.status(200).end();

                        });

                        app.get('/reset/fail', hsuProtect(id).verify, function (req, res, next) {
                            res.status(200).end();
                        });

                        app.use(tamperedErrorHandler);

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

});
