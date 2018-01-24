/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

const ip = require('ip')
const Filtering = require('./filtering')
const urlParse = require('./common/urlParse')
const appConfig = require('../js/constants/appConfig')

module.exports.resourceName = 'firewall'
// TODO: make this user-configurable for corp intranet networks, etc.
const whitelistHosts = appConfig[module.exports.resourceName].whitelistHosts

/**
 * Whether a URL is an internal address
 * @param {string} url
 */
const isInternalUrl = (url) => {
  if (!url) {
    return false
  }
  const hostname = urlParse(url).hostname
  return ip.isPrivate(hostname) || whitelistHosts.includes(hostname)
}

const onHeadersReceived = (details) => {
  const result = { resourceName: module.exports.resourceName }
  const mainFrameUrl = Filtering.getMainFrameUrl(details)
  const isIPInternal = ip.isPrivate(details.ip)
  const isUrlInternal = isInternalUrl(details.url)

  if ((isIPInternal || isUrlInternal) && !isInternalUrl(mainFrameUrl)) {
    // Block requests to local origins from non-local top-level origins
    console.log('canceling cross-boundary request', details.url, mainFrameUrl, details.ip, details.cached)
    // TODO: Make sure this works as expected for form posts
    result.cancel = true
  } else if (isIPInternal && !isUrlInternal) {
    // Block requests to an external name that resolves to an internal address
    console.log('canceling mismatched request', details.url, mainFrameUrl, details.ip, details.cached)
    result.cancel = true
  }

  return result
}

module.exports.init = () => {
  Filtering.registerHeadersReceivedFilteringCB(onHeadersReceived)
}
