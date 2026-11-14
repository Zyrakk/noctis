import React, { useRef, useState } from 'react'
import { Radar, ArrowUpLeft, ArrowRight, LockKeyhole, Eye, EyeOff, ShieldCheck, Fingerprint, BookOpen, Loader2 } from 'lucide-react'
import './login.css'

function signInMessage(error) {
  if (error.status === 401) return 'The username or password is incorrect.'
  if (error.status === 429) return 'Too many attempts. Please wait a moment and try again.'
  if (error.status >= 500) return 'Your workspace is temporarily unavailable. Please try again.'
  if (!error.status) return 'Unable to reach your workspace. Check your connection and try again.'
  return 'We couldn’t sign you in. Check your details and try again.'
}

export default function LoginScreen({ auth, navigate, destination }) {
  const [visible, setVisible] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const submitting = useRef(false)

  async function submit(event) {
    event.preventDefault()
    if (submitting.current) return
    const form = event.currentTarget
    const data = new FormData(form)
    submitting.current = true
    setPending(true)
    setError('')
    try {
      await auth.login(data.get('username'), data.get('password'))
      form.reset()
      navigate(destination)
    } catch (failure) {
      setError(signInMessage(failure))
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return <main className="v2 n-login" lang="en">
    <header className="n-login-header"><a href="/" className="n-login-brand" aria-label="Noctis, home"><Radar size={29} strokeWidth={1.35} aria-hidden="true"/><span>noctis</span></a><a href="/" className="n-login-back"><ArrowUpLeft size={15} aria-hidden="true"/>Back to overview</a></header>
    <section className="n-login-story" aria-label="Your private observatory">
      <div className="n-orbit" aria-hidden="true"><i/><i/><i/><Radar size={130} strokeWidth={.55}/><span/></div>
      <div className="n-story-copy"><p className="n-eyebrow">A PRIVATE SPACE FOR CLEARER THINKING</p><h2>From noise<br/><em>to evidence.</em></h2><p>Your research, with its context intact.<br/>Pick up the thread wherever you left off.</p></div>
      <div className="n-login-principles"><span><BookOpen size={15} aria-hidden="true"/>Source-led research</span><span><Fingerprint size={15} aria-hidden="true"/>Controlled access</span><span><ShieldCheck size={15} aria-hidden="true"/>Your judgment first</span></div>
    </section>
    <section className="n-login-form-area" aria-labelledby="sign-in-heading">
      <div className="n-login-card"><div className="n-login-lock" aria-hidden="true"><LockKeyhole size={22} strokeWidth={1.35}/></div><p className="n-eyebrow">YOUR PRIVATE OBSERVATORY</p><h1 id="sign-in-heading">Welcome back</h1><p className="n-form-intro">Sign in to your research workspace.</p>
        {auth.error && !error && <p className="n-session-notice" role="status">We couldn’t check your previous session. You can still try signing in.</p>}
        <form className="n-login-form" onSubmit={submit} aria-busy={pending}>
          <div><label htmlFor="noctis-username">Username</label><input id="noctis-username" name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} required readOnly={pending} placeholder="Your operator username" aria-describedby={error ? 'sign-in-error' : undefined}/></div>
          <div><label htmlFor="noctis-password">Password</label><div className="n-password"><input id="noctis-password" name="password" type={visible ? 'text' : 'password'} autoComplete="current-password" required readOnly={pending} placeholder="Enter your password" aria-describedby={error ? 'sign-in-error' : undefined}/><button type="button" className="n-password-toggle" aria-label={visible ? 'Hide password' : 'Show password'} aria-controls="noctis-password" aria-pressed={visible} onClick={() => setVisible(value => !value)}>{visible ? <EyeOff size={18} aria-hidden="true"/> : <Eye size={18} aria-hidden="true"/>}</button></div></div>
          {error && <p id="sign-in-error" role="alert">{error}</p>}
          <button className="n-submit" type="submit" disabled={pending}>{pending ? <><Loader2 size={17} className="n-spinner" aria-hidden="true"/><span>Signing in…</span></> : <>Sign in<ArrowRight size={17} aria-hidden="true"/></>}</button>
        </form>
        <p className="n-login-status" role="status" aria-live="polite">{pending ? 'Signing in…' : ''}</p>
        <p className="n-login-security"><ShieldCheck size={14} aria-hidden="true"/>Authorized access · Private session</p>
      </div>
      <p className="n-login-demo">Just looking around? <a href="/demo">Explore the demo <ArrowRight size={13} aria-hidden="true"/></a></p>
    </section>
    <footer className="n-login-footer"><span>NOCTIS / RESEARCH WORKSPACE</span><span>Original sources. Clear provenance. Your judgment.</span></footer>
  </main>
}
