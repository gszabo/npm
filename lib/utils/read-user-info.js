'use strict'
const Bluebird = require('bluebird')
const readAsync = Bluebird.promisify(require('read'))
const userValidate = require('npm-user-validate')
const log = require('npmlog')

exports.otp = readOTP
exports.password = readPassword
exports.username = readUsername
exports.email = readEmail

function read (opts) {
  return Bluebird.try(() => {
    log.clearProgress()
    return readAsync(opts)
  }).finally(() => {
    log.showProgress()
  })
}

function readOTP (msg, otp) {
  if (otp && /^[\d ]+$/.test(otp)) return otp.replace(/\s+/g, '')

  return read({prompt: msg, default: otp || ''})
    .then(otp => readOTP(msg, otp))
}

function readPassword (password) {
  if (password) return password

  return read({prompt: 'Password: ', silent: true, default: password || ''})
    .then(readPassword)
}

function readUsername (username, opts) {
  if (username) {
    const error = userValidate.username(username)
    if (error) {
      opts.log && opts.log.warn(error.message)
    } else {
      return username.trim()
    }
  }

  return read({prompt: 'Username: ', default: username || ''})
    .then(username => readUsername(username, opts))
}

function readEmail (email, opts) {
  if (email) {
    const error = userValidate.email(email)
    if (error) {
      opts.log && opts.log.warn(error.message)
    } else {
      return email.trim()
    }
  }

  return read({prompt: 'Email (this IS public): ', default: email || ''})
    .then(username => readEmail(username, opts))
}

