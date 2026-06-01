/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import { Helmet } from 'react-helmet-async';

const SITE_NAME = 'T1 Agentics';
const SITE_URL = 'https://t1agentics.ai';
const DEFAULT_OG_IMAGE = `${SITE_URL}/T1_Agentics_Logo.png`;

/**
 * Per-route SEO tags. Drop one of these at the top of any public page:
 *
 *   <SEO
 *     title="700+ Security Integrations"
 *     description="Browse the full T1 Agentics integration catalog..."
 *     path="/integrations"
 *   />
 *
 * Title is auto-suffixed with the site name. `path` produces a canonical URL.
 * `noindex` adds a meta robots noindex tag (use for thank-you / post-action pages).
 */
function SEO({
  title,
  description,
  path = '/',
  image = DEFAULT_OG_IMAGE,
  type = 'website',
  noindex = false,
  jsonLd = null,
}) {
  const fullTitle = title ? `${title} | ${SITE_NAME}` : `${SITE_NAME} | AI-Assisted SOC Platform`;
  const url = path.startsWith('http') ? path : `${SITE_URL}${path}`;
  const fullImage = image && image.startsWith('http') ? image : `${SITE_URL}${image || ''}`;

  return (
    <Helmet prioritizeSeoTags>
      <title>{fullTitle}</title>
      {description && <meta name="description" content={description} />}
      <link rel="canonical" href={url} />

      <meta property="og:type" content={type} />
      <meta property="og:site_name" content={SITE_NAME} />
      <meta property="og:title" content={fullTitle} />
      {description && <meta property="og:description" content={description} />}
      <meta property="og:url" content={url} />
      <meta property="og:image" content={fullImage} />

      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={fullTitle} />
      {description && <meta name="twitter:description" content={description} />}
      <meta name="twitter:image" content={fullImage} />

      {noindex
        ? <meta name="robots" content="noindex, nofollow" />
        : <meta name="robots" content="index, follow" />}

      {jsonLd && (
        <script type="application/ld+json">{JSON.stringify(jsonLd)}</script>
      )}
    </Helmet>
  );
}

export default SEO;
