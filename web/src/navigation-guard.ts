import { useEffect } from 'react'

const guards = new Set<() => boolean>()
export function allowNavigation() { return [...guards].every(check => check()) }
export function useUnsavedChanges(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return
    const check = () => window.confirm('有未保存的修改，确定放弃并离开吗？')
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = '' }
    guards.add(check); window.addEventListener('beforeunload', unload)
    return () => { guards.delete(check); window.removeEventListener('beforeunload', unload) }
  }, [dirty])
}
