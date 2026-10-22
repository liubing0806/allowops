import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

void i18n.use(initReactI18next).init({
  lng: 'zh-CN',
  fallbackLng: 'en',
  resources: {
    'zh-CN': { translation: zhCN },
    en: { translation: en },
  },
  interpolation: {
    escapeValue: false,
  },
})

export default i18n
