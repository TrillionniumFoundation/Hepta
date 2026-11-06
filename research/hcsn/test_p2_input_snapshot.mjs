import test from 'node:test';
import assert from 'node:assert/strict';
import {ExactOccupancyLedger,AddressContractError} from './p2_exact_occupancy_reference.mjs';

test('one-shot coordinate getter cannot create an unreadable zero-key slot', () => {
  const ledger = new ExactOccupancyLedger({dimension:2, capacity:2});
  let calls=0;
  const key=[1,0];
  Object.defineProperty(key,0,{configurable:true, get() { calls++; return calls===1 ? 1 : 0; }});
  assert.equal(ledger.write(key,17),'inserted');
  assert.equal(calls,1,'coordinate is read exactly once per operation');
  assert.equal(ledger.read([1,0]).status,'known');
  assert.equal(ledger.read([1,0]).value,17);
});

test('mutable getters on other coordinates cannot make a mixed-phase key', () => {
  const ledger = new ExactOccupancyLedger({dimension:3,capacity:2});
  let count=0;
  const key=[1,2,3];
  Object.defineProperty(key,1,{get(){count++;return count===1 ? 2 : 0;}});
  ledger.write(key,9);
  assert.equal(count,1);
  assert.equal(ledger.read([1,2,3]).status,'known');
});

test('non-finite coordinate on first observation is rejected before mutation', () => {
  const ledger=new ExactOccupancyLedger({dimension:2,capacity:2});
  const key=[1,0];let count=0;
  Object.defineProperty(key,0,{get(){count++;return count===1?Infinity:1;}});
  assert.throws(()=>ledger.write(key,1),AddressContractError);
  assert.equal(count,1);
  assert.equal(ledger.occupancy,0);
});

test('zero-vector after first observation remains a refusal', () => {
  const ledger=new ExactOccupancyLedger({dimension:2,capacity:2});
  const key=[0,0];let count=0;
  Object.defineProperty(key,0,{get(){count++;return count===1?0:1;}});
  assert.throws(()=>ledger.write(key,1),AddressContractError);
  assert.equal(count,1);
  assert.equal(ledger.occupancy,0);
});

test('sparse arrays are not accidentally admitted as finite keys', () => {
  const ledger=new ExactOccupancyLedger({dimension:2,capacity:1});
  assert.throws(()=>ledger.write([1, ,],1),AddressContractError);
  assert.equal(ledger.occupancy,0);
});
