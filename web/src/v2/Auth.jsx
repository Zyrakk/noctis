import React, { createContext, useContext, useEffect, useState } from 'react'
import { request } from './api.js'
const Context = createContext(null)
export function AuthProvider({ children }) {
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => { const invalidate=()=>setSession(null);window.addEventListener('noctis:unauthorized',invalidate);return()=>window.removeEventListener('noctis:unauthorized',invalidate) },[])
  useEffect(() => { let active = true; request('/auth/session').then(r => { if(active) setSession(r.data) }).catch(e => { if(active && e.status !== 401) setError(e.message) }).finally(() => { if(active) setLoading(false) }); return () => { active = false } }, [])
  async function login(username, password) { const result = await request('/auth/login', { method:'POST', body:JSON.stringify({username,password}) }); setSession(result.data) }
  async function logout() { await request('/auth/logout', { method:'POST', headers:{'X-CSRF-Token':session.csrf} }); setSession(null) }
  return <Context.Provider value={{session,loading,error,login,logout}}>{children}</Context.Provider>
}
export const useAuth = () => useContext(Context)
