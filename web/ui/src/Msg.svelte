<script>
  import { fade } from 'svelte/transition'
  /** @type {{ type: string, text: string, role?: string }} */
  let { type, text, role } = $props()
</script>

{#if text}
  <p class={type} {role} transition:fade={{ duration: 200 }}>{text}</p>
{/if}
