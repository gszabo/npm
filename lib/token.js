'use strict'
const profile = require('npm-profile')
const npm = require('./npm.js')
const output = require('./utils/output.js')
const Table = require('cli-table2')
const Bluebird = require('bluebird')
const isCidrV4 = require('is-cidr').isCidrV4
const isCidrV6 = require('is-cidr').isCidrV6
const readUserInfo = require('./utils/read-user-info.js')


module.exports = token

token.usage =
  'npm token list\n' +
  'npm token delete <tokenKey>\n' +
  'npm token create [--readonly] [--cidr=list]\n'

token.subcommands = ['list', 'delete', 'create']

token.completion = function (opts, cb) {
  var argv = opts.conf.argv.remain
  if (argv.length === 2) {
    return cb(null, access.subcommands)
  }

  switch (argv[2]) {
    case 'list':
    case 'delete':
    case 'create':
      return cb(null, [])
    default:
      return cb(new Error(argv[2] + ' not recognized'))
  }
}

function withCb (prom, cb) {
  prom.then(value => cb(null, value), cb)
}

function token (args, cb) {
  if (args.length === 0) return withCb(list([]), cb)
  switch (args[0]) {
    case 'list':
    case 'ls':
      withCb(list(), cb)
      break
    case 'delete': 
    case 'rel':
    case 'remove':
    case 'rm':
      withCb(rm(args.slice(1)), cb)
      break
    case 'create':
      withCb(create(args.slice(1)), cb)
      break
    default:
      cb(new Error('Unknown profile command: ' + args[0]))
  }
}

function generateTokenIds (tokens, minLength) {
  const byId = {}
  tokens.forEach(token => {
    token.id = token.key
    for (let ii = minLength; ii < token.key.length; ++ii) {
      if (!tokens.some(ot => ot !== token && ot.key.slice(0, ii) === token.key.slice(0, ii))) {
        token.id = token.key.slice(0, ii)
        break
      }
    }
    byId[token.id] = token
  })
  return byId
}
function list (args) {
  const json = npm.config.get('json')
  const parseable = npm.config.get('parseable')
  const registry = npm.config.get('registry')
  const otp = npm.config.get('otp')
  const auth = npm.config.getCredentialsByURI(registry)
  if (otp) auth.otp = otp
  return profile.listTokens(registry, auth).then(tokens => {
    if (json) {
      output(JSON.stringify(tokens, null, 2))
      return
    } else if (parseable) {
      output(['key', 'token', 'created', 'readonly', 'CIDR whitelist'].join('\t'))
      tokens.forEach(token => {
        output([
          token.key,
          token.token,
          token.created,
          token.readonly ? 'true' : 'false',
          token.cidr_whitelist ? token.cidr_whitelist.join(',') : ''
        ].join('\t'))
      })
      return
    }
    generateTokenIds(tokens, 6)
    const idWidth = tokens.reduce((acc, token) => Math.max(acc, token.id.length), 0)
    const table = new Table({
      head: ['id', 'token', 'created', 'readonly', 'CIDR whitelist'],
      colWidths: [Math.max(idWidth, 2) + 2, 9, 12, 10]
    })
    tokens.forEach(token => {
      table.push([
        token.id,
        token.token + '…',
        String(token.created).slice(0,10),
        token.readonly ? 'yes' : 'no',
        token.cidr_whitelist ? token.cidr_whitelist.join(', ') : ''
      ])
    })
    output(table.toString())
  })
}

function rm (args) {
  const json = npm.config.get('json')
  const parseable = npm.config.get('parseable')
  const registry = npm.config.get('registry')
  const otp = npm.config.get('otp')
  const auth = npm.config.getCredentialsByURI(registry)
  if (otp) auth.otp = otp
  const toRemove = []
  return profile.listTokens(registry, auth).then(tokens => {
    args.forEach(id => {
      const matches = tokens.filter(token => token.key.indexOf(id) === 0)
      if (matches === 1) {
        toRemove.push(matches[0])
      } else if (matches.length > 1) {
        throw new Error(`Token ID "${id}" was ambiguous, a new token may have been created since you last ran \`npm-profile token list\`.`)
      } else {
        const tokenMatches = tokens.filter(token => id.indexOf(token.token) === 0)
        if (tokenMatches === 0) {
          throw new Error(`Unknown token id or value "${id}".`)
        }
        toRemove.push(id)
      } 
    })
    return Bluebird.map(toRemove, key => profile.removeToken(key, registry, auth))
  }).then(() => {
    if (json) {
      output(JSON.stringify(toRemove))
    } else if (parseable) {
      output(toRemove.join('\t'))
    } else {
      output('Removed ' + toRemove.length + ' token' + (toRemove.length !== 1 ? 's' : ''))
    }
  })
}

function create (args) {
  const json = npm.config.get('json')
  const parseable = npm.config.get('parseable')
  const registry = npm.config.get('registry')
  const otp = npm.config.get('otp')
  const auth = npm.config.getCredentialsByURI(registry)
  if (otp) auth.otp = otp
  const cidr = npm.config.get('cidr')
  const readonly = npm.config.get('read-only')
  
  const validCIDR = validateCIDRList(cidr)
  return readUserInfo.password().then(password => {
    return profile.createToken(password, readonly, validCIDR, registry, auth).catch(ex => {
      if (ex.code !== 401 || otp) throw ex
      return Bluebird.try(() => {
        // if profile.get doesn't throw then their auth token is ok and we probably should prompt for otp
        if (ex.code !== 'otp') return profile.get(registry, auth)
      }).then(() => {
        return readUserInfo.otp('Authenticator provided OTP:')
      }).then(otp => {
        auth.otp = otp
        return profile.createToken(password, readonly, validCIDR, registry, auth)
      })
    })
  }).then(result => {
    const table = new Table({
      head: Object.keys(result)
    })
    table.push(Object.keys(result).map(k => result[k]))
    output(table.toString())
  })
}

function validateCIDR (cidr) {
  if (isCidrV6(cidr)) {
    throw new Error('CIDR whitelist can only contain IPv4 addresses, ' + cidr + ' is IPv6')
  }
  if (!isCidrV4(cidr)) {
    throw new Error('CIDR whitelist contains invalid CIDR entry: ' + cidr)
  }
}

function validateCIDRList (cidrs) {
  const list = Array.isArray(cidrs) ? cidrs : cidrs ? cidrs.split(/,\s*/) : []
  list.forEach(validateCIDR)
  return list
}
