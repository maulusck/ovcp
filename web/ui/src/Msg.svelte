<script>
  import { fade } from 'svelte/transition'
  let { type, text } = $props()
</script>

{#if text}
  <p class={type} transition:fade={{ duration: 200 }}>{text}</p>
{/if}
