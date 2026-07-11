<script>
  let html = $state('')
  let err = $state('')

  async function load() {
    try {
      const res = await fetch('/docs.html')
      if (!res.ok) throw new Error()
      html = await res.text()
    } catch { err = 'Could not load documentation.' }
  }
  load()
</script>

<div class="card docs">
  {#if err}<p class="err">{err}</p>{/if}
  {#if html}
    {@html html}
  {:else if !err}
    <p class="muted">Loading…</p>
  {/if}
</div>

<style>
  /* mandoc's own semantic classes (h1.Sh, h2.Ss, p.Pp, dl.Bl-tag, Bd-indent),
     mapped onto the app's theme instead of shipping mandoc's default CSS. */
  .docs :global(table.head) { display: none; }
  .docs :global(h1.Sh) {
    font-size: 15px; font-weight: 600; margin: 24px 0 10px;
    letter-spacing: .02em; color: var(--text);
    border-bottom: 1px solid var(--line); padding-bottom: 6px;
  }
  .docs :global(section.Sh:first-child h1.Sh) { margin-top: 0; }
  .docs :global(h2.Ss) { font-size: 13px; font-weight: 600; margin: 16px 0 6px; color: var(--dim); }
  .docs :global(a.permalink) { color: inherit; text-decoration: none; }
  .docs :global(p), .docs :global(dd) { color: var(--text); line-height: 1.6; margin: 8px 0; }
  .docs :global(b) { color: var(--amber); font-weight: 600; }
  .docs :global(i) { color: var(--dim); font-style: normal; }
  .docs :global(dl.Bl-tag) { margin: 8px 0; }
  .docs :global(dt) { font-family: var(--mono); font-size: 13px; margin-top: 14px; }
  .docs :global(.Bd-indent pre) {
    background: var(--ink); border: 1px solid var(--line); border-radius: 4px;
    padding: 10px 14px; font-family: var(--mono); font-size: 13px; overflow-x: auto;
  }
</style>
