# HSU

(HMAC signed URLs)

[![Build Status](https://travis-ci.org/smebberson/hsu.svg?branch=master)](https://travis-ci.org/smebberson/hsu)
[![Coverage Status](https://coveralls.io/repos/github/smebberson/hsu/badge.svg?branch=master)](https://coveralls.io/github/smebberson/hsu?branch=master)

Express middleware to generate and verify rolling, HMAC signed URLs. The HMAC digest is verified using information in the users session. Any previous digests are instantly replaced when a new one is created (i.e. rolling).

## Install

```
$ npm install hsu
```

## API

```
var hsu = require('hsu');
```

### hsu(options)

Creates a middleware for URL signing. This middleware adds a `req.signUrl(urlToSign)` function to make a signed URL. You need to pass a URL (`urlToSign`) to this function and it will return the original URL with a signed component.

```
var signedUrl = req.signUrl('https://domain.com/reset?user=6dg3tct749fj1&ion=1&espv=2');
console.log(signedUrl); // https://domain.com/reset?user=6dg3tct749fj1&ion=1&espv=2&signature=kV5lVrYg05wFD6KArI0HrkrwpkAHphLqTPTq1VUjmoY%3D
```

#### Options

The `hsu` function takes a required `options` object. The options object has both a required key, and an optional key.

##### Required keys

The `hsu` `options` object must have the following required key:

###### secret

A string which will be used in the HMAC digest generation.

##### Optional keys

The `hsu` `options` object can also contain any of the following optional keys:

###### sessionKey

Determines which property ('key') on `req` the session object is located. Defaults to `session` (i.e. `req.session`). The salt used to create the HMAC digest is stored and read as `req[sessionKey].hsuSalt`.

## Example

### A simple Express example

The following is an example of using HSU to generate a signed URL, and then verify it on the next request.

```
var express = require('express'),
    cookieSession = require('cookie-session')
    hsu = require('hsu');

// setup route middleware
var hsuProtect = hsu({ secret: '9*3>Ne>aKk4g)' });

// create the express app
var app = express()

// we need a session
app.use(cookieSession({ keys: ['A', 'B', 'C'] }));

// setup a route that will email the user a signed URL
app.get('/account/reset', hsuProtect, function (req, res, next) {

    var signedUrl = req.signUrl('/account/' + req.user.id + '/reset');

    // send email to user

    res.render('account-reset-email-sent');

});

// setup a route to verify the signed URL
app.get('/acount/:id/reset', hsuProtect, function (req, res, next) {

    // This will only be called if the signed URL passed
    // otherwise a HTTP status of 403 will be returned and this
    // will never execute.

    res.render('account-email-reset');

});
```

### Custom error handling

When signed URL verification fails, an error is thrown that has `err.code === 'EBADHMACDIGEST'`. This can be used to display custom error messages.

```
var express = require('express'),
    cookieSession = require('cookie-session')
    hsu = require('hsu');

// setup route middleware
var hsuProtect = hsu({ secret: '9*3>Ne>aKk4g)' });

// create the express app
var app = express()

// we need a session
app.use(cookieSession({ keys: ['A', 'B', 'C'] }));

// setup a route that will email the user a signed URL
app.get('/account/reset', hsuProtect, function (req, res, next) {

    var signedUrl = req.signUrl('/account/' + req.user.id + '/reset');

    // send email to user

    res.render('account-reset-email-sent');

});

// setup a route to verify the signed URL
app.get('/acount/:id/reset', hsuProtect, function (req, res, next) {

    // This will only be called if the signed URL passed
    // otherwise a HTTP status of 403 will be returned and this
    // will never execute.

    res.render('account-email-reset');

});

// error handler
app.use(function (err, req, res, next) {

    if (err.code !== 'EBADHMACDIGEST') {
        return next(err);
    }

    // handle HMAC digest errors here
    res.status(403).send('URL has been tampered with.');

});

```

## License

[MIT](LICENSE.md)
