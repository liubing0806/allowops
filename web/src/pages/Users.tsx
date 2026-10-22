import { useState } from 'react'
import { Controller, useFieldArray, useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api, type Role, type RoleMapping, type User } from '@/api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import {
  DataTable,
  Dialog,
  Field,
  PageTitle,
  Panel,
  QueryState,
} from '@/components/console/common'
import { commaList, requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'

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
  const [selected, setSelected] = useState<User | null>(null)

  return (
    <div className="flex flex-col gap-3">
      <PageTitle title={t('nav.users')} description={t('users.description')} />
      <Panel>
        <QueryState pending={users.isPending} error={users.error} />
        {users.data && (
          <DataTable<User>
            data={users.data.users}
            columns={[
              { accessorKey: 'username', header: t('login.username') },
              { accessorKey: 'providerId', header: t('users.provider') },
              {
                id: 'groups',
                header: t('users.groups'),
                cell: ({ row }) => row.original.groups.join(', '),
              },
              {
                id: 'roles',
                header: t('users.effective'),
                cell: ({ row }) => row.original.effectiveRoles.join(', '),
              },
              {
                id: 'assign',
                header: t('common.actions'),
                cell: ({ row }) => (
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto p-0"
                    onClick={() => setSelected(row.original)}
                  >
                    {t('users.assign', { name: row.original.username })}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Panel>
      <Panel title={t('common.role')}>
        <QueryState pending={roles.isPending} error={roles.error} />
        {roles.data && (
          <DataTable<Role>
            data={roles.data.roles}
            columns={[
              { accessorKey: 'name', header: t('common.name') },
              {
                accessorKey: 'description',
                header: t('common.description'),
                cell: ({ row }) => t(row.original.description),
              },
            ]}
          />
        )}
      </Panel>
      <QueryState pending={mappings.isPending} error={mappings.error} />
      {mappings.data && (
        <MappingEditor
          key={mappings.data.revision}
          mappings={mappings.data.mappings}
          revision={mappings.data.revision}
        />
      )}{' '}
      {selected && roles.data && (
        <RoleEditor
          user={selected}
          roles={roles.data.roles}
          onClose={() => setSelected(null)}
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
  const saving = useCommand(async (values: z.infer<typeof roleSchema>) => {
    await api.setUserRoles({
      userId: user.userId,
      manualRoles: values.manualRoles,
      expectedRevision: user.revision,
    })
    onClose()
  }, 'users.saved')

  return (
    <Dialog
      title={t('users.assign', { name: user.username })}
      onClose={onClose}
    >
      <p className="text-sm">
        {t('users.mapped')}: {user.mappedRoles.join(', ') || t('common.none')}
      </p>
      <form
        noValidate
        className="flex min-w-0 flex-col gap-3"
        onSubmit={form.handleSubmit((values) => saving.mutate(values))}
      >
        <fieldset className="flex flex-col gap-2 rounded-lg border p-3">
          <legend className="px-1 text-xs font-medium text-muted-foreground">
            {t('users.manual')}
          </legend>
          {roles.map((role) => (
            <Controller
              key={role.name}
              control={form.control}
              name="manualRoles"
              render={({ field }) => (
                <Label className="flex cursor-pointer items-center gap-2 text-sm font-normal">
                  <Checkbox
                    checked={field.value.includes(role.name)}
                    onCheckedChange={(checked) => {
                      if (checked === true) {
                        field.onChange([...field.value, role.name])
                      } else {
                        field.onChange(
                          field.value.filter((r) => r !== role.name),
                        )
                      }
                    }}
                  />
                  {role.name}
                </Label>
              )}
            />
          ))}
        </fieldset>
        <div>
          <Button size="sm" disabled={saving.isPending}>
            {t('users.save')}
          </Button>
        </div>
      </form>
    </Dialog>
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

  return (
    <Panel title={t('users.mappings')}>
      <p className="text-sm text-muted-foreground">{t('users.mappingHint')}</p>
      <QueryState pending={methodsQuery.isPending} error={methodsQuery.error} />
      <form
        noValidate
        className="flex flex-col gap-3"
        onSubmit={form.handleSubmit((values) => saving.mutate(values))}
      >
        {!methodsQuery.isPending && fields.fields.map((field, index) => {
          const currentId = watchedMappings?.[index]?.providerId ?? field.providerId
          const extraIds = [...new Set([field.providerId, currentId])].filter(
            (id) => id && !methodOptions.some((method) => method.providerId === id),
          )
          return (
            <div
              className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[120px_1fr_1fr_auto] sm:items-end"
              key={field.id}
            >
              <Field
                label={t('users.provider')}
                error={
                  form.formState.errors.mappings?.[index]?.providerId?.message
                }
              >
                <NativeSelect
                  {...form.register(`mappings.${index}.providerId`)}
                  className="w-full"
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
              </Field>
              <Field
                label={t('users.mappingGroup')}
                error={form.formState.errors.mappings?.[index]?.group?.message}
              >
                <Input {...form.register(`mappings.${index}.group`)} />
              </Field>
              <Field
                label={t('users.mappingRoles')}
                error={form.formState.errors.mappings?.[index]?.roles?.message}
              >
                <Input {...form.register(`mappings.${index}.roles`)} />
              </Field>
              <div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => fields.remove(index)}
                >
                  {t('common.delete')}
                </Button>
              </div>
            </div>
          )
        })}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
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
            {t('users.addMapping')}
          </Button>
          <Button size="sm" disabled={saving.isPending}>
            {t('users.saveMappings')}
          </Button>
        </div>
      </form>
    </Panel>
  )
}
