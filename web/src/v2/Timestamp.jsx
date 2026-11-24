import React from 'react'

export function Timestamp({value,fallback='unknown'}) {
  const date=value?new Date(value):null
  return date&&!Number.isNaN(date.getTime())?<time dateTime={value} title={value}>{new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(date)}</time>:<>{value||fallback}</>
}
