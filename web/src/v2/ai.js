import { request } from './api.js'
export const submitAIJob = (payload, csrf, { signal } = {}) => request('/ai/jobs', { method:'POST', headers:{'X-CSRF-Token':csrf}, body:JSON.stringify(payload), signal })
export const getAIJob = (id, { signal } = {}) => request(`/ai/jobs/${encodeURIComponent(id)}`, { signal })
export const cancelAIJob = (id, csrf) => request(`/ai/jobs/${encodeURIComponent(id)}/cancel`, { method:'POST', headers:{'X-CSRF-Token':csrf} })
export const executeQuery = (plan, csrf, { signal } = {}) => request('/query', { method:'POST', headers:{'X-CSRF-Token':csrf}, body:JSON.stringify({plan}), signal })
export async function readAIConfig({ signal } = {}) {
 const response=await fetch('/api/v2/ai/config',{credentials:'same-origin',headers:{Accept:'application/json'},signal})
 if(response.status===401)window.dispatchEvent(new Event('noctis:unauthorized'))
 let body;try{body=await response.json()}catch{throw new Error('Respuesta del servidor no válida')};if(!response.ok){const e=new Error(body.error?.message||'Configuración no disponible');e.status=response.status;throw e}
 return {...body,etag:response.headers.get('ETag')}
}
export const saveAIConfig = (config,etag,csrf) => request('/ai/config',{method:'PUT',headers:{'X-CSRF-Token':csrf,'If-Match':etag},body:JSON.stringify(config)})
export const validateAIConfig = (config,csrf) => request('/ai/validate',{method:'POST',headers:{'X-CSRF-Token':csrf},body:JSON.stringify(config)})
