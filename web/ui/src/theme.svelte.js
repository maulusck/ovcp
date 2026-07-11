// Local UI theme preference — a browser-side toggle, not a server setting.
const KEY = 'ovcp_theme'

// name, label, and the two colors used to preview it in the dropdown itself.
export const THEMES = [
  { name: 'default', label: 'Default', bg: '#171f28', fg: '#e0a136' },
  { name: 'matrix', label: 'Matrix', bg: '#0a0f0a', fg: '#33ff33' },
  { name: 'retrocrt', label: 'RetroCRT', bg: '#120a02', fg: '#ffb000' },
  { name: 'frutiger', label: 'Frutiger', bg: '#eaf6fb', fg: '#1f7fb8' },
]

export const theme = $state({ name: localStorage.getItem(KEY) || 'default' })
apply(theme.name)

export function setTheme(name) {
  theme.name = name
  localStorage.setItem(KEY, name)
  apply(name)
}

function apply(name) {
  document.documentElement.dataset.theme = name
}
