import { createContext, useContext } from 'react'

// Layout owns the 52px top bar; pages render their title into it through
// PageTitle. Outside the layout (login) PageTitle renders in place.
export const PageHeaderContext = createContext<{
  slot: HTMLElement | null
} | null>(null)

export const usePageHeaderSlot = () => useContext(PageHeaderContext)
