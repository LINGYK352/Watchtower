/** Render document content with an explicit allowlist and no outbound resources. */
export function safeReportHtml(html: string): string {
  const source = document.createElement('template')
  source.innerHTML = html
  const output = document.createElement('div')
  const allowed = new Set('p span div h1 h2 h3 h4 h5 h6 strong em b i u ul ol li table thead tbody tfoot tr td th br hr pre code blockquote sup sub img'.split(' '))
  const drop = new Set('script style iframe object embed form input button meta link base svg math'.split(' '))
  function copy(node: Node, parent: Node) {
    if (node.nodeType === Node.TEXT_NODE) { parent.appendChild(document.createTextNode(node.textContent || '')); return }
    if (!(node instanceof Element)) return
    const tag = node.tagName.toLowerCase()
    if (drop.has(tag)) return
    if (!allowed.has(tag)) { Array.from(node.childNodes).forEach(child => copy(child, parent)); return }
    const element = document.createElement(tag)
    if (tag === 'img') {
      const src = node.getAttribute('src') || ''
      if (!/^data:image\/(?:png|jpeg|gif|webp);base64,[a-z0-9+/=\s]+$/i.test(src)) return
      element.setAttribute('src', src);element.setAttribute('alt', node.getAttribute('alt') || '')
    }
    for (const attribute of ['colspan', 'rowspan']) {
      const value = node.getAttribute(attribute)
      if ((tag === 'td' || tag === 'th') && value && /^[1-9]\d{0,2}$/.test(value)) element.setAttribute(attribute, value)
    }
    Array.from(node.childNodes).forEach(child => copy(child, element))
    parent.appendChild(element)
  }
  Array.from(source.content.childNodes).forEach(node => copy(node, output))
  return output.innerHTML
}
