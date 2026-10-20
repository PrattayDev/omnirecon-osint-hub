export default async function handler(req, res) {
  const { domain } = req.query;

  if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return res.status(400).json({ error: 'Valid domain parameter is required.' });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'OSINT-Portfolio-Auditor/1.0' }
    });

    clearTimeout(timeout);

    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const securityChecks = [
      { header: 'strict-transport-security', label: 'HSTS (Strict-Transport-Security)' },
      { header: 'content-security-policy', label: 'Content-Security-Policy (CSP)' },
      { header: 'x-frame-options', label: 'X-Frame-Options' },
      { header: 'x-content-type-options', label: 'X-Content-Type-Options' },
      { header: 'referrer-policy', label: 'Referrer-Policy' },
      { header: 'permissions-policy', label: 'Permissions-Policy' }
    ];

    const audit = securityChecks.map(check => ({
      label: check.label,
      header: check.header,
      present: Boolean(headers[check.header]),
      value: headers[check.header] || 'Missing'
    }));

    return res.status(200).json({
      status: response.status,
      finalUrl: response.url,
      server: headers['server'] || 'Hidden / Not disclosed',
      poweredBy: headers['x-powered-by'] || 'Hidden / Not disclosed',
      audit,
      rawHeaders: headers
    });
  } catch (error) {
    return res.status(502).json({
      error: 'Unable to reach target over HTTPS.',
      details: error.message
    });
  }
}