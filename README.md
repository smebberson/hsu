# HSU

(HMAC signed URLs)

[![npm](https://img.shields.io/npm/v/hsu.svg)](https://www.npmjs.com/package/hsu)
[![Build Status](https://travis-ci.org/smebberson/hsu.svg?branch=master)](https://travis-ci.org/smebberson/hsu)
[![Coverage Status](https://coveralls.io/repos/github/smebberson/hsu/badge.svg?branch=master)](https://coveralls.io/github/smebberson/hsu?branch=master)

Express middleware to generate and verify rolling, HMAC signed, timed URLs. The HMAC digest is verified using information in the users session. Any previous digests are instantly replaced when a new one is created (i.e. rolling). You can have concurrent signed URLs for the same user.

There are three stages to HSU:

- The create stage in which a signed URL is created (i.e. password reset form in which the users email address is collected).
- The verify stage in which a URL is protected unless the signed URL is verified (i.e. the password reset form in which the new password is collected, the link to this form usually comes from an email).
- The complete stage in which the URL has been consumed and is removed such that it can't be used again (i.e. the users password was successfully reset; we don't want that URL to be able to reset their password again).

HSU also aims to meet the following goals:

- The route should be locked down to the device in which the request was made.
- No one should have access to the password reset route (verify stage) unless they have a verifiable signed URL.
- You should be able to restart the process at anytime, at which point, all previous signed URLs become unusable.
- One the process has been completed, all previous signed URLs become unusable.
- A signed URL should only be valid for a limited amount of time (1 hour by default).

## Install

```
$ npm install hsu
```

## API

```
var hsu = require('hsu');
```

### hsu(options)

Creates a function (i.e. `hsuProtect`) which is called with an `id` to scope the middleware (allows multiple signed URLs to be in affect for the one user concurrently).

```
var hsuProtect = hsu({ secret: '4B[>9=&DziVm7' });
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

###### ttl

The number of seconds the URL should be valid for. Defaults to 1 hour (i.e. 3600 seconds).

### hsuProtect(id)

_**Please note:** `hsuProtect` is not part of the actual API it's just the name of the variable holding the function produced by calling `hsu(options)`._

Generates three different middleware, all scoped to the `id`, one for each stage of the process (i.e. setup, verify and complete).

`id` scoping allows you to allows multiple signed URLs to be in affect for the one user concurrently. The `id` semantically should represent the process:

```
hsuProtect('verify-primary-email').setup // Function
hsuProtect('verify-primary-email').verify // Function
hsuProtect('verify-primary-email').complete // Function

hsuProtect('verify-recovery-email').setup // Function
hsuProtect('verify-recovery-email').verify // Function
hsuProtect('verify-recovery-email').complete // Function
```

#### hsuProtect(id).setup

This middleware adds a `req.signUrl(urlToSign)` function to make a signed URL. You need to pass a URL (`urlToSign`) to this function and it will return the original URL with a signed component.

```
var signedUrl = req.signUrl('https://domain.com/reset?user=6dg3tct749fj1&ion=1&espv=2');
console.log(signedUrl); // https://domain.com/reset?user=6dg3tct749fj1&ion=1&espv=2&signature=kV5lVrYg05wFD6KArI0HrkrwpkAHphLqTPTq1VUjmoY%3D
```

#### hsuProtect(id).verify

This middleware will 403 on all requests that are not verifiable signed URLs.

#### hsuProtect(id).complete

This middleware adds a `req.hsuComplete()` function that will mark a current signed URL as complete and render it unusable. Future requests to the same URL will 403.

Use the `req.hsuComplete()` function only after your process has completed. For example, in the case of a password reset, only once you're database has been successfully updated with a new password. This allows the user to request the signed URL multiple times with success, before completing the process.

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

// setup an email that requests a users password
app.get('/account/reset', function (req, res, next) {

    res.render('account-reset-email');

});

// setup a route that will email the user a signed URL
app.post('/account/reset', hsuProtect('account-reset').setup, function (req, res, next) {

    var signedUrl = req.signUrl('/account/' + req.user.id + '/reset');

    // send email to user

    res.render('account-reset-email-sent');

});

// setup a route to verify the signed URL
app.get('/acount/:id/reset', hsuProtect('account-reset').verify, function (req, res, next) {

    // This will only be called if the signed URL passed
    // otherwise a HTTP status of 403 will be returned and this
    // will never execute.

    res.render('account-new-password');

});

// setup a route to complete the process
app.post('/account/:id/reset', hsuProtect('account-reset').complete, function (req, res, next) {

    // update the database with the new password

    // render the signed URL unusable
    req.hsuComplete();

    res.render('account-new-password-complete');

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

// setup an email that requests a users password
app.get('/account/reset', function (req, res, next) {

    res.render('account-reset-email');

});

// setup a route that will email the user a signed URL
app.post('/account/reset', hsuProtect('account-reset').setup, function (req, res, next) {

    var signedUrl = req.signUrl('/account/' + req.user.id + '/reset');

    // send email to user

    res.render('account-reset-email-sent');

});

// setup a route to verify the signed URL
app.get('/acount/:id/reset', hsuProtect('account-reset').verify, function (req, res, next) {

    // This will only be called if the signed URL passed
    // otherwise a HTTP status of 403 will be returned and this
    // will never execute.

    res.render('account-new-password');

});

// setup a route to complete the process
app.post('/account/:id/reset', hsuProtect('account-reset').complete, function (req, res, next) {

    // update the database with the new password

    // render the signed URL unusable
    req.hsuComplete();

    res.render('account-new-password-complete');

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

## Change log

[Review the change log for all changes.](CHANGELOG.md)

## License

[MIT](LICENSE.md)
