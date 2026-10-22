import { create } from 'zustand'

export interface HostsFilter {
  selector: string
  hostname: string
  online: string
  agentVersion: string
}

interface HostsFilterState extends HostsFilter {
  setFilter: (patch: Partial<HostsFilter>) => void
  reset: () => void
}

const initial: HostsFilter = {
  selector: '',
  hostname: '',
  online: '',
  agentVersion: '',
}

export const useHostsFilterStore = create<HostsFilterState>()((set) => ({
  ...initial,
  setFilter: (patch) => set(patch),
  reset: () => set(initial),
}))
