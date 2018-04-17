#!/usr/bin/env node

'use strict';

const _ = require('lodash');
const fs = require('fs');
const fetch = require('node-fetch');
const sshpk = require('sshpk');
const crypto = require('crypto');
const VError = require('verror');

// const readPrivateKey = () => (fs.readFileSync('./id_rsa.secret').toString());
// const sign = (message, privateKey) => {
//   const sign = crypto.createSign('SHA256');
//   sign.update(message);
//   return sign.sign(privateKey, 'hex')
// };

const verify = (message, publicKey, signature) => {
  const verify = crypto.createVerify('SHA256');
  verify.update(message);
  return verify.verify(publicKey, signature, 'base64');
};

const fetchNotOkError = (res, body) => (
  new VError({
    name: 'FetchNotOkError',
    info: {
      url: res.url,
      status: res.status,
      body
    }
  }, `Received ${res.status} response when calling customer API.`)
);

const handleResponseIfNotOk = (res) => {
  if (!res.ok) {
    return res.text().then(body => Promise.reject(fetchNotOkError(res, body)));
  }
  return res;
};

const getGitHubUserKeys = (user) => (
  fetch(`https://api.github.com/users/${user}/keys`)
    .then(handleResponseIfNotOk)
    .then(_.method('json'))
    .then(ghKeys => _.map(ghKeys, _.property('key')))
    .then(sshKeys => (
      _.map(sshKeys, sshKey => sshpk.parseKey(sshKey).toString('pkcs1'))
    ))
);

const getGitHubDeployKeys = (repo) => {
  const githubUsername = process.env.GITHUB_USER;
  const githubToken = process.env.GITHUB_TOKEN;
  const basicAuth = Buffer.from(`${githubUsername}:${githubToken}`).toString('base64');
  return fetch(`https://api.github.com/repos/${repo}/keys`, { headers: { Authorization: `Basic ${basicAuth}` }})
    .then(handleResponseIfNotOk)
    .then(_.method('json'))
    .then(ghKeys => _.map(ghKeys, _.property('key')))
    .then(sshKeys => (
      _.map(sshKeys, sshKey => sshpk.parseKey(sshKey).toString('pkcs1'))
    ))
};

const getKeys = (message) => {
  const { user, repo, time } = message;
  if (user) {
    console.log(`> getting GitHub user keys for ${user}...`);
    return getGitHubUserKeys(user);
  } else {
    console.log(`> getting GitHub deploy keys for ${repo}...`);
    return getGitHubDeployKeys(repo)
  }
};

const rawPayload = fs.readFileSync('/dev/stdin').toString();
const jsonPayload = JSON.parse(rawPayload);
const rawMessage = jsonPayload.message;
const message = JSON.parse(jsonPayload.message);
const { signature } = jsonPayload;

console.info('>>> claim to verify:', { message, signature }, '<<<');

return getKeys(message)
  .then(keys => {
    console.log('> verifying message signature against GitHub keys...');
    const goodKey = _.find(keys, key => verify(rawMessage, key, signature));
    if (goodKey) {
      console.log('> signature looks good. I trust you.')
    } else {
      return Promise.reject(new VError({ name: 'BadSignatureError', info: { message, keys }}));
    }
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
