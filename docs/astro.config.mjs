// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';
import fs from 'node:fs';

// Load custom Tamarin grammar for syntax highlighting
const tamarinGrammar = JSON.parse(
	fs.readFileSync(new URL('./src/grammars/tamarin.tmLanguage.json', import.meta.url), 'utf-8')
);

// https://astro.build/config
export default defineConfig({
	site: 'https://docs.specmon.io',
	integrations: [
		sitemap(),
		starlight({
			title: 'SpecMon',
			description: 'Runtime monitoring of formal specifications',
			logo: {
				src: './src/assets/specmon-logo.svg',
				alt: 'SpecMon Logo',
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/specmon/specmon' }
			],
			expressiveCode: {
				shiki: {
					langs: [
						{
							...tamarinGrammar,
							aliases: ['tamarin', 'spthy'],
						},
					],
				},
			},
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'What is SpecMon?', slug: 'index' },
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Quick Start', slug: 'getting-started/quick-start' },
					],
				},
				{
					label: 'Writing Specifications',
					items: [
						{ label: 'Specification Basics', slug: 'specifications/basics' },
						{ label: 'SpecMon Annotations', slug: 'specifications/annotations' },
						{ label: 'Creating Unified Models', slug: 'specifications/unified-models' },
						{ label: 'Encoding Message Formats', slug: 'specifications/message-formats' },
						{ label: 'Event Rewriting', slug: 'specifications/rewriting' },
					],
				},
				{
					label: 'Instrumentation',
					items: [
						{ label: 'Using Frida', slug: 'instrumentation/frida' },
						{ label: 'Using go-annotate', slug: 'instrumentation/go-annotate' },
					],
				},
				{
					label: 'Reference',
					items: [
					{ label: 'Event Format', slug: 'reference/event-format' },
					{ label: 'Built-in Functions', slug: 'reference/built-in-functions' },
					{ label: 'CLI Commands', slug: 'reference/cli' },
					],
				},
				{
					label: 'Research',
					items: [
						{ label: 'Publications', slug: 'research/publications' },
					],
				},
			],
			components: {
				Footer: './src/components/Footer.astro',
			},
			customCss: ['./src/styles/global.css'],
		}),
	],
	vite: {
		plugins: [tailwindcss()],
	},
});
