import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldCheck } from 'lucide-react'
import { api } from '@/api'
import { redirectToLogin } from '@/api/navigation'
import { Field, QueryState } from '@/components/console/common'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'

const schema = z.object({
  username: requiredText,
  password: z.string().min(1, 'error.required'),
})

export default function Login() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const client = useQueryClient()
  const methods = useQuery({
    queryKey: ['loginMethods'],
    queryFn: () => api.getLoginMethods(),
  })
  const oidcProviders = methods.data?.methods.filter(
    (method) => method.kind === 'oidc',
  )
  const ldapProvider = methods.data?.methods.find(
    (method) => method.kind === 'ldap',
  )
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { username: '', password: '' },
  })
  const ldap = useCommand(async () => {
    const values = form.getValues()
    try {
      await api.loginLdap({
        ...values,
        providerId: ldapProvider?.providerId ?? '',
        client: 'LOGIN_CLIENT_CONSOLE',
      })
      client.clear()
      navigate('/')
    } finally {
      form.resetField('password')
    }
  })
  const oidc = useCommand(async (providerId: string) => {
    const result = await api.beginOidcLogin({
      providerId,
      client: 'LOGIN_CLIENT_CONSOLE',
    })
    redirectToLogin(result.authorizationUrl)
  })

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center gap-4 p-4">
      <section className="flex flex-col items-center gap-1 text-center">
        <span className="grid size-10 place-items-center rounded-xl bg-primary text-primary-foreground">
          <ShieldCheck aria-hidden="true" className="size-5" />
        </span>
        <p className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
          {t('app.name')}
        </p>
        <h1 className="text-xl font-semibold">{t('login.title')}</h1>
        <p className="text-sm text-muted-foreground">{t('login.description')}</p>
      </section>
      <Card>
        <CardContent className="flex flex-col gap-4">
          <label className="flex items-center justify-end gap-2 text-xs text-muted-foreground">
            {t('common.language')}
            <NativeSelect
              value={i18n.language}
              onChange={(event) =>
                void i18n.changeLanguage(event.target.value)
              }
            >
              <option value="zh-CN">{t('common.zh')}</option>
              <option value="en">{t('common.en')}</option>
            </NativeSelect>
          </label>
          <QueryState pending={methods.isPending} error={methods.error} />
          {oidcProviders?.map((provider) => (
            <Button
              key={provider.providerId}
              className="w-full"
              disabled={oidc.isPending}
              onClick={() => oidc.mutate(provider.providerId)}
            >
              {oidcProviders.length === 1
                ? t('login.oidc')
                : t('login.oidcProvider', { name: provider.displayName })}
            </Button>
          ))}
          <h2 className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
            {t('login.ldap')}
          </h2>
          <form
            noValidate
            className="flex flex-col gap-3"
            onSubmit={form.handleSubmit(() => ldap.mutate())}
          >
            <Field
              label={t('login.username')}
              error={form.formState.errors.username?.message}
            >
              <Input autoComplete="username" {...form.register('username')} />
            </Field>
            <Field
              label={t('login.password')}
              error={form.formState.errors.password?.message}
            >
              <Input
                type="password"
                autoComplete="current-password"
                {...form.register('password')}
              />
            </Field>
            <Button
              type="submit"
              className="w-full"
              disabled={ldap.isPending || !ldapProvider}
            >
              {t('login.submit')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
