import dns from 'dns';

// Common email domain patterns for popular providers
export const PROVIDER_RULES = {
  'gmail.com': /^[a-z0-9](\.?[a-z0-9]){5,}@gmail\.com$/i,
  'yahoo.com': /^[a-z0-9](\.?[a-z0-9]){5,}@yahoo\.com$/i,
  'outlook.com': /^[a-z0-9](\.?[a-z0-9]){5,}@outlook\.com$/i,
  'hotmail.com': /^[a-z0-9](\.?[a-z0-9]){5,}@hotmail\.com$/i,
  'icloud.com': /^[a-z0-9](\.?[a-z0-9]){5,}@icloud\.com$/i,
  'protonmail.com': /^[a-z0-9](\.?[a-z0-9]){5,}@protonmail\.com$/i,
  'zoho.com': /^[a-z0-9](\.?[a-z0-9]){5,}@zoho\.com$/i,
  'aol.com': /^[a-z0-9](\.?[a-z0-9]){5,}@aol\.com$/i
};

// Educational domain patterns
const EDUCATIONAL_DOMAINS = [
  '.edu', 
  '.ac.', 
  '.sch.',
  'edu.',
  'ac.',
  'school.',
  'college.',
  'university.',
  'institute.'
];

export const validateEmail = (email) => {
  // Basic email regex (RFC 5322 compliant)
  const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  const emailStr = String(email).toLowerCase();
  
  // First validate basic format
  if (!re.test(emailStr)) {
    return false;
  }

  // Extract domain
  const domain = emailStr.split('@')[1];
  
  // Check if we have specific rules for this domain
  if (domain && PROVIDER_RULES[domain]) {
    return PROVIDER_RULES[domain].test(emailStr);
  }

  // If no specific rules, just use basic validation
  return true;
};

export const suggestEmailCorrection = (email) => {
  if (!email || !email.includes('@')) return null;
  
  const [localPart, domain] = email.toLowerCase().split('@');
  
  // Only fix common domain typos - don't change local part
  const domainCorrections = {
    'gmai.com': 'gmail.com',
    'gmaill.com': 'gmail.com',
    'gmal.com': 'gmail.com',
    'gmial.com': 'gmail.com',
    'gmail.con': 'gmail.com',
    'gmail.co': 'gmail.com',
    'gmail.cm': 'gmail.com',
    'yaho.com': 'yahoo.com',
    'yhoo.com': 'yahoo.com',
    'yahoo.con': 'yahoo.com',
    'yahoo.co': 'yahoo.com',
    'hotmal.com': 'hotmail.com',
    'hotmail.con': 'hotmail.com',
    'hotmail.co': 'hotmail.com',
    'outlok.com': 'outlook.com',
    'outlook.con': 'outlook.com',
    'icloud.con': 'icloud.com',
    'protonmail.con': 'protonmail.com'
  };

  // Only correct if we have a known typo
  if (domainCorrections[domain]) {
    return `${localPart}@${domainCorrections[domain]}`;
  }

  return null;
};

// Verify domain existence through DNS MX records
export const verifyEmailDomain = async (email) => {
  try {
    const domain = email.split('@')[1];
    return new Promise((resolve) => {
      dns.resolveMx(domain, (err) => {
        resolve(!err);
      });
    });
  } catch {
    return false;
  }
};

// Check if email is from educational institution
export const isEducationalEmail = (email) => {
  const domain = email.split('@')[1] || '';
  return EDUCATIONAL_DOMAINS.some(pattern => domain.includes(pattern));
};