// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2021  flexiWAN Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const { escapeRegExp } = require('./security');

// Maximum length of a filter value
const MAX_FILTER_VALUE_LENGTH = 256;
// Supported filter operations
const FILTER_OPERATIONS = [
  '==', '!=', 'contains', '!contains', '<', '>', '<=', '>=', 'in', 'in last days'
];

// Fields that must not be used for filtering or sorting, to prevent leaking their values
const SENSITIVE_FIELD =
  /^(devicetoken|token|hash|salt|emailtokens|mfa|key|psk)$|secret|password|privatekey/i;

/**
 * Check that a field path (filter key or sort field) is safe to use in a query:
 * only letters, digits, '_', '-', '.', and not a sensitive field
 * @param {string} field - field path, e.g. 'interfaces.name'
 * @return {boolean}
 */
const isValidFieldPath = (field) => {
  if (typeof field !== 'string' || field.length === 0 || field.length > 100) return false;
  if (!/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(field)) return false;
  return !field.split('.').some(part => SENSITIVE_FIELD.test(part));
};

/**
 * Check that a filter is well formed, throws an error if not
 * @param {Object} filter a filter object from API request
 */
const validateFilter = ({ key, op, val }) => {
  const err = new Error('There is an error in filter');
  err.status = 400;
  if (typeof key !== 'string' ||
    !key.split('|').every(k => isValidFieldPath(k.replace(/\?/g, 'A')))) {
    throw err;
  }
  if (!FILTER_OPERATIONS.includes(op)) throw err;
  const isValidValue = v => v === null || ['undefined', 'number', 'boolean'].includes(typeof v) ||
    (typeof v === 'string' && v.length <= MAX_FILTER_VALUE_LENGTH);
  if (Array.isArray(val)) {
    if (op !== 'in' || val.length > 1000 || !val.every(isValidValue)) throw err;
  } else if (!isValidValue(val)) {
    throw err;
  }
};

/**
 * Converts API query filter operation to mongoose expression
 * @param {Object} filter a filter object from API request
 * @param {String} filter.key Key to be filtered by
 * @param {String} filter.op filter operation [==, !=, contains...]
 * @param {String} filter.val Value to be filtered
 * @returns {Object} Mongoose expression for the $match stage
*/
const getFilterExpression = ({ key, op, val }) => {
  // The key is required
  if (!key) return undefined;
  // Two sides case '?' means 'A' && 'B' - for example "device?.name" be replaced by
  // 'cond': [{"deviceA.name": "DeviceName"}, {"deviceB.name": "DeviceName"}]
  // where 'cond' depends on 'op' - if negative it will be '$and' and '$or' if opposite
  // Example: 'op' is '==' or 'contains' the condition in that case will be
  // { $or: [{"deviceA.name": "DeviceName"}, {"deviceB.name": "DeviceName"}] }
  const cond = op.includes('!') ? '$and' : '$or';
  if (key.includes('?')) {
    return {
      [cond]: ['A', 'B'].map(side => {
        const sideKey = key.replace(/\?/g, side);
        const expr = getFilterExpression({ key: sideKey, op, val });
        if (cond === '$and') {
          // we need to ignore null values for negative conditions
          return { $or: [{ [sideKey]: null }, expr] };
        }
        return expr;
      })
    };
  }
  // similar to '?', just the 'key' includes several keys divided by '|'
  if (key.includes('|')) {
    return {
      [cond]: key.split('|').map(key => getFilterExpression({ key, op, val }))
    };
  }
  // Special case for dates filtering
  if (['time', 'date', 'created_at', 'lastResolvedStatusChange'].includes(key)) {
    const date1 = new Date(val);
    const date2 = new Date(val);
    date2.setDate(date1.getDate() + 1); // beginning of the next day
    switch (op) {
      case '==':
        return { $and: [{ [key]: { $gte: date1 } }, { [key]: { $lt: date2 } }] };
      case '!=':
        return { $and: [{ [key]: { $lt: date1 } }, { [key]: { $gte: date2 } }] };
      case 'in last days':
        date1.setDate(date1.getDate() - 3); // let's do the last 3 days...
        return { $and: [{ [key]: { $lt: date1 } }, { [key]: { $gte: date2 } }] };
      case '<':
        return { [key]: { $lt: date1 } };
      case '>':
        return { [key]: { $gte: date2 } };
      case '<=':
        return { [key]: { $lt: date2 } };
      case '>=':
        return { [key]: { $gte: date1 } };
      default:
        return undefined;
    }
  }
  // all other types
  const isString = typeof val === 'string';
  // user input is matched literally
  const escVal = escapeRegExp(val);
  switch (op) {
    case '==':
      return { [key]: isString ? new RegExp('^' + escVal + '$', 'i') : val };
    case '!=':
      return { [key]: isString ? { $not: new RegExp('^' + escVal, 'i') } : { $ne: val } };
    case 'contains':
      return { [key]: new RegExp(escVal, 'i') };
    case '!contains':
      return { [key]: new RegExp('^((?!' + escVal + ').)*$', 'i') };
    case '<':
      return { [key]: { $lt: val } };
    case '>':
      return { [key]: { $gt: val } };
    case '<=':
      return { [key]: { $lte: val } };
    case '>=':
      return { [key]: { $gte: val } };
    case 'in':
      if (!Array.isArray(val)) val = val.split(',');
      return { [key]: { $in: val } };
    default:
      return undefined;
  }
};

/**
 * Check if object passes array of filters
 * @param {Object} obj an object to test if it passes filters
 * @param {Array}  filters an array of filters from API request
 * @returns {boolean} returns true if passed
*/
const passFilters = (obj, filters) => {
  // if no filters then returns true
  if (!Array.isArray(filters) || filters.length === 0) return true;
  // the object must pass every filter
  return filters.every(({ key, op, val }) => {
    if (!key || !op) return false;
    try {
      validateFilter({ key, op, val });
    } catch (err) {
      return false;
    }
    const props = key.split('.');
    let objVal = obj;
    // the key can be complex, like 'data.message.title'
    for (const prop of props) {
      if (objVal[prop] === undefined) return false;
      objVal = objVal[prop];
    }
    // must be the same type to compare
    switch (typeof objVal) {
      case 'number':
        val = +val; break;
      case 'boolean':
        val = val === true || val === 'true'; break;
    }
    const isString = typeof val === 'string';
    // user input is matched literally
    const escVal = escapeRegExp(val);
    switch (op) {
      case '==':
        return isString ? (new RegExp('^' + escVal + '$', 'i')).test(objVal) : val === objVal;
      case '!=':
        return isString ? !(new RegExp('^' + escVal + '$', 'i')).test(objVal) : val !== objVal;
      case '<=':
        return objVal <= val;
      case '>=':
        return objVal >= val;
      case '<':
        return objVal < val;
      case '>':
        return objVal > val;
      case 'contains':
        return (new RegExp(escVal, 'i')).test(objVal);
      case '!contains':
        return (new RegExp('^((?!' + escVal + ').)*$', 'i')).test(objVal);
      case 'in':
        if (!Array.isArray(val)) val = val.split(',');
        return val.includes(objVal);
      default:
        return false;
    }
  });
};

/**
 * Converts array of filters from API request to array of mongoose expressions
 * @param {Array}  filters an array of filters from API request
 * @returns {Array} an array of mongoose match expressions
 */
const getMatchFilters = (filters) => {
  const matchFilters = [];
  if (!Array.isArray(filters)) throw new Error('There is an error in filters');
  for (const filter of filters) {
    if (!filter || typeof filter !== 'object') {
      throw new Error('There is an error in filter: ' + JSON.stringify(filter));
    }
    validateFilter(filter);
    const filterExpr = getFilterExpression(filter);
    if (filterExpr !== undefined) {
      matchFilters.push(filterExpr);
    } else {
      throw new Error('There is an error in filter: ' + JSON.stringify(filter));
    }
  }
  return matchFilters;
};

/**
 * Validate sort parameters, throws an error if not valid
 * @param {string} sortField - field to sort by
 * @param {string} sortOrder - asc or desc
 */
const validateSort = (sortField, sortOrder) => {
  if (sortField === undefined || sortField === null || sortField === '') return;
  const err = new Error('Invalid sort parameters');
  err.status = 400;
  if (!isValidFieldPath(sortField)) throw err;
  if (sortOrder !== undefined && sortOrder !== null &&
    !(typeof sortOrder === 'string' && ['asc', 'desc'].includes(sortOrder.toLowerCase()))) {
    throw err;
  }
};

module.exports = {
  getMatchFilters,
  passFilters,
  validateSort,
  isValidFieldPath
};
