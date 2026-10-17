// Local UI theme preference — a browser-side toggle, not a server setting.
const KEY = 'ovcp_theme'

// name, label, and the two colors used to preview it in the dropdown itself.
export const THEMES = [
  { name: 'default', label: 'Default', bg: '#171f28', fg: '#e0a136' },
  { name: 'matrix', label: 'Matrix', bg: '#030603', fg: '#39ff14' },
  { name: 'retrocrt', label: 'RetroCRT', bg: '#14100b', fg: '#ffcf4d' },
  { name: 'frutiger', label: 'Frutiger', bg: '#e3f2f0', fg: '#0d6b80' },
  { name: 'teletext', label: 'Teletext', bg: '#000000', fg: '#ffdd00' },
]

export const theme = $state({ name: localStorage.getItem(KEY) || 'default' })
apply(theme.name)

/** @param {string} name */
export function setTheme(name) {
  theme.name = name
  localStorage.setItem(KEY, name)
  apply(name)
}

/** @param {string} name */
function apply(name) {
  document.documentElement.dataset.theme = name
}
