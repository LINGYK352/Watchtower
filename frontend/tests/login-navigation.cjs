const assert = require('node:assert/strict');
const {loginDestination, navigateAfterLogin} = require('../../validation/auth-logic/navigationAfterLogin.js');
const origin='http://127.0.0.1:55576';
const router=()=>({currentRoute:{value:{path:'/login'}},resolve:(to)=>({matched:to.startsWith('/missing')?[]:[{}]}),replace:async()=>{}});
(async()=>{
 let count=0;
 for(const input of [undefined,null,[], '/login','/login?redirect=/login','/login/','//example.com','https://example.com','/\\example.com','/foo\nbar','/missing']){
  assert.equal(loginDestination(input,origin,router()),'/dashboard');count++;
 }
 assert.equal(loginDestination('/pentest?session=qa#messages',origin,router()),'/pentest?session=qa#messages');count++;
 let r=router(),calls=[];r.replace=async target=>{r.currentRoute.value.path=target;};
 assert.equal(await navigateAfterLogin(r,'/dashboard',x=>calls.push(x)),'spa');assert.deepEqual(calls,[]);count++;
 r=router();r.replace=()=>Promise.reject(new Error('failed dynamic import'));
 assert.equal(await navigateAfterLogin(r,'/dashboard',x=>calls.push(x)),'reload');assert.deepEqual(calls,['/dashboard']);count++;
 r=router();r.currentRoute.value.path='/login/';
 assert.equal(await navigateAfterLogin(r,'/dashboard',x=>calls.push(x)),'reload');count++;
 r=router();r.replace=()=>new Promise(()=>{});calls=[];
 assert.equal(await navigateAfterLogin(r,'/dashboard',x=>calls.push(x),5),'reload');assert.deepEqual(calls,['/dashboard']);count++;
 r=router();r.replace=async()=>{r.currentRoute.value.path='/about/manual';return {type:8};};calls=[];
 assert.equal(await navigateAfterLogin(r,'/dashboard',x=>calls.push(x)),'spa');assert.deepEqual(calls,[]);count++;
 console.log(JSON.stringify({cases:count,passed:true}));
})().catch(e=>{console.error(e);process.exit(1)});
