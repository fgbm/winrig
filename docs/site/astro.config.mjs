// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://starlight.astro.build/reference/configuration/
export default defineConfig({
	site: 'https://fgbm.github.io',
	base: '/winrig',
	integrations: [
		starlight({
			title: 'winrig',
			defaultLocale: 'root',
			locales: {
				root: { label: 'English', lang: 'en' },
				ru: { label: 'Русский', lang: 'ru' },
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/fgbm/winrig' },
			],
			sidebar: [
				{
					label: 'Start',
					translations: { ru: 'Начало' },
					items: [
						{ label: 'Overview', translations: { ru: 'Обзор' }, link: '/' },
						{ label: 'Install', translations: { ru: 'Установка' }, link: '/start/install/' },
						{ label: 'Quick start', translations: { ru: 'Быстрый старт' }, link: '/start/quick-start/' },
						{ label: 'Clients', translations: { ru: 'Клиенты' }, link: '/start/clients/' },
					],
				},
				{
					label: 'Reference',
					translations: { ru: 'Справочник' },
					items: [
						{ label: 'Configuration', translations: { ru: 'Конфигурация' }, link: '/reference/configuration/' },
						{ label: 'Tools', translations: { ru: 'Инструменты' }, link: '/reference/tools/' },
					],
				},
				{
					label: 'Security',
					translations: { ru: 'Безопасность' },
					items: [
						{ label: 'Security model', translations: { ru: 'Модель безопасности' }, link: '/security/model/' },
					],
				},
			],
		}),
	],
});
