import { mount } from 'svelte'
import App from './App.svelte'
export default mount(App, { target: /** @type {HTMLElement} */ (document.getElementById('app')) })
