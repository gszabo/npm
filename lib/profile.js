'use strict'
const profile = require('npm-profile')
const npm = require('./npm.js')
const log = require('npmlog')
const output = require('./utils/output.js')
const mapToRegistry = require('./utils/map-to-registry.js')
const qw = require('qw')
const Table = require('cli-table2')
const ansistyles = require('ansistyles')
const Bluebird = require('bluebird')
const readUserInfo = require('./utils/read-user-info.js')
const qrcodeTerminal = require('qrcode-terminal')
const url = require('url')
const queryString = require('query-string')

module.exports = profileCmd

profileCmd.usage =
  'npm profile enable-2fa [auth-only|auth-and-writes]\n' +
  'npm profile disable-2fa\n' +
  'npm profile get\n' +
  'npm profile set\n'

profileCmd.subcommands = ['enable-2fa', 'disable-2fa', 'get', 'set']

profileCmd.completion = function (opts, cb) {
  var argv = opts.conf.argv.remain
  if (argv.length === 2) {
    return cb(null, access.subcommands)
  }

  switch (argv[2]) {
    case 'enable-2fa':
    case 'enable-tfa':
      if (argv.length === 3) {
        return cb(null, ['auth-only', 'auth-and-writes'])
      } else {
        return cb(null, [])
      }
    case 'disable-2fa':
    case 'disable-tfa':
    case 'get':
    case 'set':
      return cb(null, [])
    default:
      return cb(new Error(argv[2] + ' not recognized'))
  }
}

function withCb (prom, cb) {
  prom.then(value => cb(null, value), cb)
}

function profileCmd (args, cb) {
  if (args.length === 0) return cb(new Error(profileCmd.usage))
  switch (args[0]) {
    case 'enable-2fa':
    case 'enable-tfa':
    case 'enable2fa':
    case 'enabletfa':
      withCb(enable2fa(args.slice(1)), cb)
      break
    case 'disable-2fa': 
    case 'disable-tfa':
    case 'disable2fa': 
    case 'disabletfa':
      withCb(disable2fa(), cb)
      break
    case 'get':
      withCb(get(args.slice(1)), cb)
      break
    case 'set':
      withCb(set(args.slice(1)), cb)
      break
    default:
      cb(new Error('Unknown profile command: ' + args[0]))
  }
}

function config() {
  const conf = {
    json: npm.config.get('json'),
    parseable: npm.config.get('parseable'),
    registry: npm.config.get('registry'),
    otp: npm.config.get('otp')
  }
  conf.auth = npm.config.getCredentialsByURI(conf.registry)
  if (conf.otp) conf.auth.otp = conf.otp
  return conf
}

const knownProfileKeys = qw`
  name email ${'two factor auth'} cidr_whitelist fullname homepage
  freenode twitter github created updated`

function get (args) {
  const tfa = 'two factor auth'
  const conf = config()
  return profile.get(conf).then(info => {
    delete info['cidr_whitelist']
    if (conf.json) {
      output(JSON.stringify(info, null, 2))
      return
    }
    const cleaned = {}
    knownProfileKeys.forEach(k => cleaned[k] = info[k] || '')
    Object.keys(info).filter(k => !(k in cleaned)).forEach(k => cleaned[k] = info[k] || '')
    delete cleaned.tfa
    delete cleaned.email_verified
    cleaned['email'] += info.email_verified ? ' (verified)' : '(unverified)'
    if (info.tfa) {
      if (info.tfa.pending) {
        cleaned[tfa] = 'pending'
      } else {
        cleaned[tfa] = info.tfa.mode
      }
    } else {
      cleaned[tfa] = 'disabled'
    }
    if (args.length) {
      const values = args // comma or space separated ↓
        .join(',').split(/,/).map(arg => arg.trim()).filter(arg => arg !== '')
        .map(arg => cleaned[arg])
        .join('\t')
      output(values)
    } else {
      if (conf.parseable) {
        Object.keys(info).forEach(key => {
          if (key === 'tfa') {
            output(`${key}\t${cleaned[tfa]}`)
          } else {
            output(`${key}\t${info[key]}`)
          }
        })
        return
      } else {
        const table = new Table()
        Object.keys(cleaned).forEach(k => table.push({[ansistyles.bright(k)]: cleaned[k]}))
        output(table.toString())
      }
    }
  })
}

const writableProfileKeys = qw`
  email password fullname homepage freenode twitter github`

function set (args) {
  if (args.length !== 2) {
    return Promise.reject(Error('npm profile set <prop> <value>'))
  }
  const conf = config()
  const prop = args[0].toLowerCase().trim()
  const value = args[1]
  if (writableProfileKeys.indexOf(prop) === -1) {
    return Promise.reject(Error(`"${prop}" is not a property we can set. Valid properties are: ` + writableProfileKeys.join(', ')))
  }
  return Bluebird.try(() => {
    if (prop !== 'password') return
    return readUserInfo.password().then(password => {
    })
  }).then(() => {
    const conf = config()
    // FIXME: Work around to not clear everything other than what we're setting
    return profile.get(conf).then(user => {
      const newUser = {}
      writableProfileKeys.forEach(k => newUser[k] = user[k])
      newUser[prop] = value
      return profile.set(newUser, conf).then(result => {
        if (conf.json) {
          output(JSON.stringify({[prop]: result[prop]}, null, 2))
        } else if (conf.parseable) {
          otuput(prop + '\t' + result[prop])
        } else {
          output('Set', prop, 'to', result[prop])
        }
      })
    })
  })
}

function enable2fa (args) {
  if (args.length > 1) {
    return Promise.reject(new Error('npm profile enable-2fa [auth-only|auth-and-writes]'))
  }
  const mode = args[0] || 'auth-only'
  if (mode !== 'auth-only' && mode !== 'auth-and-writes') {
    return Promise.reject(new Error(`Invalid two factor authentication mode "${mode}".\n` +
      'Valid modes are:\n' +
      '  auth-only - Require two-factor authentication only when logging in\n' +
      '  auth-and-writes - Require two-factor authentication when logging in AND when publishing'))
  }
  const conf = config()
  if (conf.json || conf.parseable) {
    return Promise.reject(new Error(
      'Enabling two-factor authentication is an interactive opperation and '+
      (json ? 'JSON' : 'parseable') + 'output mode is not available'))
  }
  log.notice('profile', 'Enabling two factor authentication for ' + mode)
  const info = {
    tfa: {
      mode: mode
    }
  }
  return readUserInfo.password().then(password => {
    info.tfa.password = password
    return profile.get(conf).then(info => {
      if (!info.tfa) return
      if (info.tfa.pending) {
        log.info('profile', 'Resetting two-factor authentication')
        return profile.set({tfa: {password, mode: 'disable'}}, conf)
      } else {
        if (conf.auth.otp) return
        return readUserInfo.otp('Enter OTP:  ').then(otp => {
          conf.auth.otp = otp
        })
      }
    })
  }).then(() => {
    log.info('profile', 'Setting two factor authentication to ' + mode)
    return profile.set(info, conf)
  }).then(challenge => {
    if (challenge.tfa === null) {
      output('Two factor authentication mode changed to: ' + mode)
      return
    }
    if (typeof challenge.tfa !== 'string' || !/^otpauth:[/][/]/.test(challenge.tfa)) {
      throw new Error('Unknown error enabling two-factor authentication. Expected otpauth URL, got: ' + challenge.tfa)
    }
    const otpauth = url.parse(challenge.tfa)
    const opts = queryString.parse(otpauth.query)
    return qrcode(challenge.tfa).then(code => {
      output('Scan into your authenticator app:\n' + code + '\n Or enter code:', opts.secret)
    }).then(code => {
      return readUserInfo.otp('And enter your first OTP code:  ')
    }).then(otp1 => {
      return readUserInfo.otp('And enter your second OTP code: ').then(otp2 => [otp1, otp2])
    }).then(otps => {
      log.info('profile', 'Finalizing two factor authentication')
      return profile.set({tfa: otps}, conf)
    }).then(result => {
      output('TFA successfully enabled. Below are your recovery codes, please print these out.')
      output('You will need these to recover access to your account if you lose your authentication device.')
      result.tfa.forEach(c => output('\t' + c))
    })
  })
}

function disable2fa (args) {
  const conf = config()
  return readUserInfo.password().then(password => {
    if (conf.auth.otp) return
    return readUserInfo.otp('Enter one-time password from your authenticator: ').then(otp => {
      conf.auth.otp = otp
    })
  }).then(() => {
    return profile.set({tfa: {password: password, mode: 'disable'}}, conf).then(() => {
      if (json) {
        output(JSON.stringify({tfa: false}, null, 2))
      } else if (parseable) {
        output('tfa\tfalse')
      } else {
        output('Two factor authentication disabled.')
      }
    })
  })
}

function qrcode (url) {
  return new Promise(resolve => qrcodeTerminal.generate(url, resolve))
}
