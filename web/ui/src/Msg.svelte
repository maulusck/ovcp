<script>
  import { fade } from 'svelte/transition'
  let { type, text, role } = $props()
</script>

{#if text}
  <p class={type} {role} transition:fade={{ duration: 200 }}>{text}</p>
{/if}
