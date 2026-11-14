const filterKeys=['source_id','case_id','kind']
const entities=['observations','cases','entities','observables']

// The API remains authoritative for filter IDs, cursor validity and text bounds.
// Check the conversion contract here so an unsupported plan is never reinterpreted.
function planError(plan){
 if(!plan||plan.version!=='1'||plan.operation!=='search')return 'Unsupported query plan version or operation.'
 if(!entities.includes(plan.entity)||!['exact','fulltext'].includes(plan.mode))return 'Unsupported query entity or mode.'
 if(typeof plan.text!=='string'||!plan.filters||typeof plan.filters!=='object'||Array.isArray(plan.filters)||Object.entries(plan.filters).some(([key,value])=>!filterKeys.includes(key)||typeof value!=='string')||(plan.cursor!==undefined&&typeof plan.cursor!=='string'))return 'Invalid query plan fields.'
 if(!Number.isInteger(plan.limit)||plan.limit<1||plan.limit>100)return 'Limit must be a whole number from 1 to 100.'
 return ''
}

export function readTypedQuery(url){
 const params=url.searchParams,limitValue=params.get('limit')??'50',filters={}
 for(const key of filterKeys)if(params.has(key))filters[key]=params.get(key)
 const plan={version:params.get('version')??'1',operation:params.get('operation')??'search',entity:params.get('entity_type')??'observations',mode:params.get('mode')??'exact',text:params.get('q')??'',filters,limit:Number(limitValue),...(params.has('cursor')?{cursor:params.get('cursor')}:{})}
 const error=/^[0-9]+$/.test(limitValue)?planError(plan):'Limit must be a whole number from 1 to 100.'
 return {plan,limitValue,error,started:params.get('run_query')==='1'||plan.text!==''}
}

export function typedQueryURL(url,plan){
 const error=planError(plan)
 if(error)throw new Error(error)
 const next=new URL(url)
 next.searchParams.delete('evidence')
 for(const [key,value]of Object.entries({run_query:'1',version:plan.version,operation:plan.operation,q:plan.text,entity_type:plan.entity,mode:plan.mode,limit:String(plan.limit)}))next.searchParams.set(key,value)
 for(const key of filterKeys)Object.hasOwn(plan.filters,key)?next.searchParams.set(key,plan.filters[key]):next.searchParams.delete(key)
 plan.cursor===undefined?next.searchParams.delete('cursor'):next.searchParams.set('cursor',plan.cursor)
 return next
}

export function editedTypedQueryURL(url,values){
 const next=new URL(url)
 next.searchParams.delete('cursor')
 next.searchParams.delete('evidence')
 for(const [key,value]of Object.entries({...values,run_query:'1',version:'1',operation:'search'}))next.searchParams.set(key,value)
 return next
}
