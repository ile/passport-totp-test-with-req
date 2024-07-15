/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , OTPAuth = require("otpauth");


/**
 * `Strategy` constructor.
 *
 * The TOTP authentication strategy authenticates requests based on the
 * TOTP value submitted through an HTML-based form.
 *
 * Applications must supply a `setup` callback which accepts `user`, and then
 * calls the `done` callback supplying a `key` and `period` used to verify the
 * TOTP value.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `codeField`  field name where the HOTP value is found, defaults to _code_
 *   - `window`     size of time step delay window, defaults to 6
 *
 * Examples:
 *
 *     passport.use(new TotpStrategy(
 *       function(user, done) {
 *         TotpKey.findOne({ userId: user.id }, function (err, key) {
 *           if (err) { return done(err); }
 *           return done(null, key.key, key.period);
 *         });
 *       }
 *     ));
 *
 * References:
 *  - [TOTP: Time-Based One-Time Password Algorithm](http://tools.ietf.org/html/rfc6238)
 *  - [KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
 *
 * @param {Object} options
 * @param {Function} setup
 * @api public
 */
function Strategy(options, setup) {
  if (typeof options == 'function') {
    setup = options;
    options = {};
  }
  
  this._codeField = options.codeField || 'code';
  this._window = options.window !== undefined ? options.window : 6;
  
  passport.Strategy.call(this);
  this._setup = setup;
  this.name = 'totp-test';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on TOTP values.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var token = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);
  
  var self = this;
  this._setup(req, req.user, function(err, secret, period) {
    if (err) { return self.error(err); }

		// Create a new TOTP object.
		let totp = new OTPAuth.TOTP({
			// Algorithm used for the HMAC function.
			algorithm: "SHA1",
			// Length of the generated tokens.
			digits: 6,
			// Interval of time for which a token is valid, in seconds.
			period,
			// Arbitrary key encoded in Base32 or OTPAuth.Secret instance.
			secret, // or 'OTPAuth.Secret.fromBase32("NB2W45DFOIZA")'
		});
	
		// Validate a token (returns the token delta or null if it is not found in the
		// search window, in which case it should be considered invalid).
		let delta = totp.validate({ token, window: 1 });

		if (delta === null) {
			return self.fail();
		}	    

    return self.success(req.user);
  });
    
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
