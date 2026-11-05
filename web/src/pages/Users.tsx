import { useState } from 'react'
import { Controller, useFieldArray, useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { PlusIcon, SearchIcon, XIcon } from 'lucide-react'
import { api, type Role, type RoleMapping, type User } from '@/api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { DataTable, PageTitle, QueryState } from '@/components/console/common'
import { SidePanel } from '@/components/console/SidePanel'
import { commaList, requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'
import { cn } from '@/lib/utils'

const roleSchema = z.object({ manualRoles: z.array(z.string()) })
const mappingSchema = z.object({
  mappings: z.array(
    z.object({
      providerId: requiredText,
      group: requiredText,
      roles: requiredText,
    }),
  ),
})

const initials = (user: User) =>
  (user.displayName || user.username).slice(0, 2).toUpperCase()

function Chips({
  items,
  variant,
}: {
  items: string[]
  variant: 'group' | 'mapped' | 'manual'
}) {
  if (!items.length) return <span className="text-muted-foreground">—</span>
  return (
    <span className="flex flex-wrap gap-1">
      {items.map((item) => (
        <span
          key={item}
          className={cn(
            'rounded-[5px] px-1.5 font-mono text-[11px]',
            variant === 'group' &&
              'border border-dashed border-border text-foreground-2',
            variant === 'mapped' && 'bg-muted text-foreground-2',
            variant === 'manual' && 'bg-accent text-accent-foreground',
          )}
        >
          {item}
        </span>
      ))}
    </span>
  )
}

export default function Users() {
  const { t } = useTranslation()
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => api.listUsers(),
  })
  const roles = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.listRoles(),
  })
  const mappings = useQuery({
    queryKey: ['roleMappings'],
    queryFn: () => api.getRoleMappings(),
  })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const needle = search.trim().toLowerCase()
  const allUsers = users.data?.users ?? []
  const shown = allUsers.filter(
    (user) =>
      !needle ||
      [user.displayName, user.username, user.email].some((value) =>
        value.toLowerCase().includes(needle),
      ),
  )
  const selected = allUsers.find((user) => user.userId === selectedId)

  return (
    <div className="flex flex-col gap-4">
      <PageTitle
        title={t('nav.users')}
        description={t('users.description')}
        action={
          <label className="relative block w-full sm:w-60">
            <span className="sr-only">{t('users.search')}</span>
            <SearchIcon
              aria-hidden="true"
              className="absolute top-2 left-2.5 size-4 text-muted-foreground"
            />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t('users.searchPlaceholder')}
              className="h-8 bg-card pl-8"
            />
          </label>
        }
      />
      <section
        aria-label={t('common.role')}
        className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2.5"
      >
        <QueryState pending={roles.isPending} error={roles.error} />
        {roles.data?.roles.map((role) => (
          <div
            key={role.name}
            className="flex flex-col gap-1 rounded-xl border bg-card px-3.5 py-3"
          >
            <span className="flex items-center gap-2">
              <span className="flex-1 font-mono font-medium">{role.name}</span>
              {users.data && (
                <span className="font-mono text-[11px] text-muted-foreground">
                  {t('users.memberCount', {
                    count: allUsers.filter((user) =>
                      user.effectiveRoles.includes(role.name),
                    ).length,
                  })}
                </span>
              )}
            </span>
            <span className="text-xs text-foreground-2">
              {t(role.description)}
            </span>
          </div>
        ))}
      </section>
      <section
        aria-label={t('users.list')}
        className="min-w-0 overflow-hidden rounded-xl border bg-card px-2 pb-2"
      >
        <QueryState pending={users.isPending} error={users.error} />
        {users.data && (
          <div className="overflow-x-auto">
            <DataTable<User>
              data={shown}
              pageSize={50}
              rowClassName={(user) =>
                user.userId === selectedId
                  ? 'bg-selection shadow-[inset_2px_0_0_var(--primary)] hover:bg-selection'
                  : undefined
              }
              columns={[
                {
                  accessorKey: 'username',
                  header: t('users.user'),
                  cell: ({ row }) => {
                    const user = row.original
                    return (
                      <span className="flex min-w-0 items-center gap-2.5">
                        <span
                          aria-hidden="true"
                          className="grid size-7 shrink-0 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground"
                        >
                          {initials(user)}
                        </span>
                        <span className="flex min-w-0 flex-col leading-tight">
                          <button
                            type="button"
                            aria-label={t('users.assign', {
                              name: user.username,
                            })}
                            aria-pressed={user.userId === selectedId}
                            onClick={() => setSelectedId(user.userId)}
                            className="self-start text-left font-medium text-primary underline-offset-4 hover:underline"
                          >
                            {user.displayName || user.username}
                          </button>
                          <span className="truncate font-mono text-[11px] text-muted-foreground">
                            {[user.username, user.email]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        </span>
                      </span>
                    )
                  },
                },
                {
                  accessorKey: 'providerId',
                  header: t('users.provider'),
                  cell: ({ row }) => (
                    <span className="font-mono text-xs text-foreground-2">
                      {row.original.providerId}
                    </span>
                  ),
                },
                {
                  id: 'groups',
                  header: t('users.groups'),
                  cell: ({ row }) => (
                    <Chips items={row.original.groups} variant="group" />
                  ),
                },
                {
                  id: 'mapped',
                  header: t('users.mapped'),
                  cell: ({ row }) => (
                    <Chips items={row.original.mappedRoles} variant="mapped" />
                  ),
                },
                {
                  id: 'manual',
                  header: t('users.manual'),
                  cell: ({ row }) => (
                    <Chips items={row.original.manualRoles} variant="manual" />
                  ),
                },
                {
                  id: 'roles',
                  header: t('users.effective'),
                  cell: ({ row }) => (
                    <span className="font-mono text-xs font-medium">
                      {row.original.effectiveRoles.join(', ') || '—'}
                    </span>
                  ),
                },
              ]}
            />
          </div>
        )}
      </section>
      <QueryState pending={mappings.isPending} error={mappings.error} />
      {mappings.data && (
        <MappingEditor
          key={mappings.data.revision}
          mappings={mappings.data.mappings}
          revision={mappings.data.revision}
        />
      )}
      {selected && roles.data && (
        <RoleEditor
          key={`${selected.userId}/${selected.revision}`}
          user={selected}
          roles={roles.data.roles}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  )
}

function RoleEditor({
  user,
  roles,
  onClose,
}: {
  user: User
  roles: Role[]
  onClose: () => void
}) {
  const { t } = useTranslation()
  const form = useForm<z.infer<typeof roleSchema>>({
    resolver: zodResolver(roleSchema),
    defaultValues: { manualRoles: user.manualRoles },
  })
  const manual = useWatch({ control: form.control, name: 'manualRoles' })
  const saving = useCommand(async (values: z.infer<typeof roleSchema>) => {
    await api.setUserRoles({
      userId: user.userId,
      manualRoles: values.manualRoles,
      expectedRevision: user.revision,
    })
    onClose()
  }, 'users.saved')
  const effective = [...new Set([...user.mappedRoles, ...(manual ?? [])])]

  return (
    <SidePanel
      title={t('users.assign', { name: user.displayName || user.username })}
      subtitle={
        <span className="font-mono">
          {user.username} · {user.providerId}
        </span>
      }
      onClose={onClose}
    >
      <form
        noValidate
        className="flex min-w-0 flex-col gap-3"
        onSubmit={form.handleSubmit((values) => saving.mutate(values))}
      >
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1.5 text-xs font-medium text-muted-foreground">
            {t('users.manual')}
          </legend>
          {roles.map((role) => {
            // Roles granted by a group mapping are shown checked and locked;
            // the manual role list itself is saved unchanged for them.
            const mapped = user.mappedRoles.includes(role.name)
            const descriptionId = `role-${role.name}-description`
            return (
              <Controller
                key={role.name}
                control={form.control}
                name="manualRoles"
                render={({ field }) => {
                  const checked = mapped || field.value.includes(role.name)
                  return (
                    <label
                      className={cn(
                        'flex items-start gap-2.5 rounded-lg border px-2.5 py-2',
                        mapped ? 'cursor-default' : 'cursor-pointer',
                        checked && 'border-accent bg-selection',
                      )}
                    >
                      <Checkbox
                        className="mt-0.5"
                        aria-label={role.name}
                        aria-describedby={descriptionId}
                        checked={checked}
                        disabled={mapped}
                        onCheckedChange={(next) => {
                          if (next === true) {
                            field.onChange([...field.value, role.name])
                          } else {
                            field.onChange(
                              field.value.filter((r) => r !== role.name),
                            )
                          }
                        }}
                      />
                      <span className="flex min-w-0 flex-1 flex-col">
                        <span className="flex items-center gap-1.5">
                          <span className="font-mono font-medium">
                            {role.name}
                          </span>
                          {mapped && (
                            <span className="text-[11px] text-muted-foreground">
                              {t('users.fromMapping')}
                            </span>
                          )}
                        </span>
                        <span
                          id={descriptionId}
                          className="text-xs text-foreground-2"
                        >
                          {t(role.description)}
                        </span>
                      </span>
                    </label>
                  )
                }}
              />
            )
          })}
        </fieldset>
        <p className="border-t border-border-subtle pt-3 text-xs text-muted-foreground">
          {t('users.mappingHint')}{' '}
          <span className="font-mono text-foreground">
            {effective.join(', ') || t('common.none')}
          </span>
        </p>
        <div className="flex justify-end">
          <Button disabled={saving.isPending}>{t('users.save')}</Button>
        </div>
      </form>
    </SidePanel>
  )
}

function MappingEditor({
  mappings,
  revision,
}: {
  mappings: RoleMapping[]
  revision: string
}) {
  const { t } = useTranslation()
  const form = useForm<z.infer<typeof mappingSchema>>({
    resolver: zodResolver(mappingSchema),
    defaultValues: {
      mappings: mappings.map((m) => ({ ...m, roles: m.roles.join(',') })),
    },
  })
  const fields = useFieldArray({ control: form.control, name: 'mappings' })
  const methodsQuery = useQuery({
    queryKey: ['loginMethods'],
    queryFn: () => api.getLoginMethods(),
  })
  const methodOptions = methodsQuery.data?.methods ?? []
  const watchedMappings = useWatch({ control: form.control, name: 'mappings' })
  const saving = useCommand(async (values: z.infer<typeof mappingSchema>) => {
    await api.saveRoleMappings({
      expectedRevision: revision,
      mappings: values.mappings.map((m) => ({
        ...m,
        roles: commaList(m.roles),
      })),
    })
  }, 'users.mappingsSaved')
  const errors = form.formState.errors.mappings
  const error = (message?: string) =>
    message && (
      <small role="alert" className="text-xs text-destructive">
        {t(message)}
      </small>
    )

  return (
    <section className="min-w-0 overflow-hidden rounded-xl border bg-card">
      <header className="flex flex-wrap items-center gap-2 border-b border-border-subtle px-4 py-3">
        <h2 className="flex-1 text-sm font-semibold">{t('users.mappings')}</h2>
        <span className="text-xs text-muted-foreground">
          {t('users.mappingDescription')}
        </span>
      </header>
      <QueryState pending={methodsQuery.isPending} error={methodsQuery.error} />
      <form
        noValidate
        className="flex flex-col"
        onSubmit={form.handleSubmit((values) => saving.mutate(values))}
      >
        {!methodsQuery.isPending && fields.fields.map((field, index) => {
          const currentId = watchedMappings?.[index]?.providerId ?? field.providerId
          const extraIds = [...new Set([field.providerId, currentId])].filter(
            (id) => id && !methodOptions.some((method) => method.providerId === id),
          )
          return (
            <div
              className="flex flex-wrap items-start gap-2 border-b border-border-subtle px-4 py-2"
              key={field.id}
            >
              <label className="flex w-full flex-col gap-1 sm:w-40">
                <span className="sr-only">{t('users.provider')}</span>
                <NativeSelect
                  {...form.register(`mappings.${index}.providerId`)}
                  className="w-full font-mono text-xs"
                >
                  {[
                    ...methodOptions.map((method) => ({
                      id: method.providerId,
                      label: method.displayName,
                    })),
                    ...extraIds.map((id) => ({
                      id,
                      label: t('users.unconfiguredProvider', { id }),
                    })),
                  ].map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label}
                    </option>
                  ))}
                </NativeSelect>
                {error(errors?.[index]?.providerId?.message)}
              </label>
              <label className="flex min-w-40 flex-1 flex-col gap-1">
                <span className="sr-only">{t('users.mappingGroup')}</span>
                <Input
                  placeholder={t('users.mappingGroup')}
                  className="h-8 font-mono text-xs"
                  {...form.register(`mappings.${index}.group`)}
                />
                {error(errors?.[index]?.group?.message)}
              </label>
              <span aria-hidden="true" className="leading-8 text-muted-foreground">
                →
              </span>
              <label className="flex min-w-48 flex-[2] flex-col gap-1">
                <span className="sr-only">{t('users.mappingRoles')}</span>
                <Input
                  placeholder={t('users.mappingRoles')}
                  className="h-8 font-mono text-xs"
                  {...form.register(`mappings.${index}.roles`)}
                />
                {error(errors?.[index]?.roles?.message)}
              </label>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                className="mt-0.5"
                aria-label={t('users.removeMapping')}
                onClick={() => fields.remove(index)}
              >
                <XIcon />
              </Button>
            </div>
          )
        })}
        <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
          <Button
            type="button"
            variant="outline"
            className="border-dashed text-foreground-2"
            onClick={() =>
              fields.append({
                providerId:
                  methodOptions[0]?.providerId ??
                  mappings[0]?.providerId ??
                  '',
                group: '',
                roles: '',
              })
            }
          >
            <PlusIcon />
            {t('users.addMapping')}
          </Button>
          <span className="flex-1" />
          {form.formState.isDirty && (
            <span className="text-xs text-warning">{t('users.unsaved')}</span>
          )}
          <Button disabled={saving.isPending}>{t('users.saveMappings')}</Button>
        </div>
      </form>
    </section>
  )
}
