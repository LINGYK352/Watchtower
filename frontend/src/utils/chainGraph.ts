import type { AttackChain, ChainStep } from '../api/intel'
export type ChainNode={id:string;kind:'entry'|'step'|'end';index:number;seq:number;x:number;y:number;severity:string;step?:ChainStep;label?:string;target?:string}
export const NODE_WIDTH=256,NODE_HEIGHT=152
const GAP_X=90,GAP_Y=42,MARGIN=40
const aliases:Record<string,string>={'严重':'critical','危急':'critical',crit:'critical',critical:'critical','高危':'high','高':'high',high:'high','中危':'medium','中':'medium',moderate:'medium',medium:'medium','低危':'low','低':'low',low:'low','信息':'info','无':'info',info:'info',informational:'info'}
export function chainSeverity(value:unknown):string{return aliases[String(value??'').trim().toLowerCase()]||'unknown'}
function targetOf(step:ChainStep,chain:AttackChain):string{
 const value=String(step.source_site||step.target||chain.unit||'').trim()
 try{return new URL(value.includes('://')?value:'http://'+value).origin}catch{return value||chain.unit||'—'}
}
/** Explicit parent links form branches. Chronological adjacency is never causation. */
export function buildChainLayout(chain:AttackChain|null,_columns=3){
 const raw=Array.isArray(chain?.steps)?chain!.steps:[],steps=raw.filter(s=>s&&typeof s==='object'),nodes:ChainNode[]=[],roots:ChainNode[]=[],parents=new Map<string,string>(),byId=new Map<string,ChainNode>(),bySeq=new Map<number,ChainNode>(),byTarget=new Map<string,ChainNode>()
 if(!chain)return {nodes,edges:[],width:320,height:240,stepCount:0,invalidCount:0}
 for(const [index,step] of steps.entries()){
  const target=targetOf(step,chain)
  if(!byTarget.has(target)){const root:ChainNode={id:'target-'+byTarget.size,kind:'entry',index:-1,seq:0,x:0,y:0,severity:'entry',label:target,target};byTarget.set(target,root);roots.push(root);nodes.push(root)}
  const node:ChainNode={id:'step-'+index,kind:'step',index,seq:Number(step.seq)||index+1,x:0,y:0,severity:chainSeverity(step.severity),step,target}
  nodes.push(node);byId.set(node.id,node)
  if(step.step_id)byId.set(step.step_id,node)
  if(step.finding_ref&&!byId.has('finding:'+step.finding_ref))byId.set('finding:'+step.finding_ref,node)
  if(!bySeq.has(node.seq))bySeq.set(node.seq,node)
 }
 let invalidParents=0
 for(const node of nodes.filter(n=>n.kind==='step')){
  const step=node.step!,parent=step.parent_step_id?byId.get(step.parent_step_id):step.parent_finding_ref?byId.get('finding:'+step.parent_finding_ref):step.parent_seq?bySeq.get(Number(step.parent_seq)):undefined
  // Only a recorded earlier step can be a parent. This also handles corrupt
  // legacy cycles/forward references without recursion or invented relations.
  if(parent&&parent.kind==='step'&&parent.index<node.index)parents.set(node.id,parent.id)
  else {parents.set(node.id,byTarget.get(node.target!)!.id);if(step.parent_step_id||step.parent_finding_ref||step.parent_seq)invalidParents++}
 }
 const children=new Map<string,ChainNode[]>()
 for(const node of nodes){const p=parents.get(node.id);if(p){const list=children.get(p)||[];list.push(node);children.set(p,list)}}
 for(let i=roots.length-1;i>=0;i--)if(!children.get(roots[i].id)?.length){const root=roots.splice(i,1)[0];nodes.splice(nodes.indexOf(root),1)}
 let lane=0,maxDepth=0
 for(const root of roots){
  const stack:{node:ChainNode;depth:number;visited:boolean}[]=[{node:root,depth:0,visited:false}]
  while(stack.length){const item=stack.pop()!,kids=children.get(item.node.id)||[]
   if(!item.visited){stack.push({...item,visited:true});for(let i=kids.length-1;i>=0;i--)stack.push({node:kids[i],depth:item.depth+1,visited:false})}
   else{item.node.x=MARGIN+item.depth*(NODE_WIDTH+GAP_X);item.node.y=kids.length?(kids[0].y+kids[kids.length-1].y)/2:MARGIN+lane++*(NODE_HEIGHT+GAP_Y);maxDepth=Math.max(maxDepth,item.depth)}
  }
 }
 const nodeMap=new Map(nodes.map(n=>[n.id,n])),edges=nodes.filter(n=>parents.has(n.id)).map(node=>{const parent=nodeMap.get(parents.get(node.id)!)!,x1=parent.x+NODE_WIDTH,y1=parent.y+NODE_HEIGHT/2,x2=node.x,y2=node.y+NODE_HEIGHT/2,mid=(x1+x2)/2;return {id:parent.id+'>'+node.id,from:parent.id,to:node.id,path:`M ${x1} ${y1} C ${mid} ${y1} ${mid} ${y2} ${x2-4} ${y2}`,crossSession:!!parent.step?.session_id&&!!node.step?.session_id&&parent.step.session_id!==node.step.session_id}})
 return {nodes,edges,width:MARGIN*2+(maxDepth+1)*NODE_WIDTH+maxDepth*GAP_X,height:Math.max(240,MARGIN*2+lane*(NODE_HEIGHT+GAP_Y)-GAP_Y),stepCount:steps.length,invalidCount:raw.length-steps.length+invalidParents}
}
