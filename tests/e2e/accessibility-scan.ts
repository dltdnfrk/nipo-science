import type { Page } from "@playwright/test";

export type AccessibilityViolation = Readonly<{
  detail: string;
  rule: string;
  selector: string;
}>;

export async function scanAccessibility(page: Page): Promise<readonly AccessibilityViolation[]> {
  return page.evaluate(() => {
    const violations: AccessibilityViolation[] = [];
    const add = (rule: string, element: Element, detail: string): void => {
      const id = element.id ? `#${element.id}` : "";
      const classes = [...element.classList].map((name) => `.${name}`).join("");
      violations.push({ detail, rule, selector: `${element.localName}${id}${classes}` });
    };
    const isVisible = (element: Element): boolean => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && box.width > 0 && box.height > 0;
    };
    const accessibleName = (element: Element): string => {
      const labelledBy = element.getAttribute("aria-labelledby");
      if (labelledBy) {
        return labelledBy
          .split(/\s+/u)
          .map((id) => document.getElementById(id)?.textContent ?? "")
          .join(" ")
          .trim();
      }
      const ariaLabel = element.getAttribute("aria-label")?.trim();
      if (ariaLabel) return ariaLabel;
      if (element instanceof HTMLInputElement && element.labels?.length) {
        return [...element.labels].map((label) => label.textContent ?? "").join(" ").trim();
      }
      if (
        (element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement) &&
        element.labels?.length
      ) {
        return [...element.labels].map((label) => label.textContent ?? "").join(" ").trim();
      }
      return (element.textContent ?? element.getAttribute("title") ?? "").trim();
    };
    const rgb = (value: string): readonly [number, number, number, number] | null => {
      const match = value.match(/^rgba?\((\d+)[, ]+(\d+)[, ]+(\d+)(?:[, /]+([\d.]+))?\)$/u);
      if (!match) return null;
      return [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4] ?? "1")];
    };
    const luminance = (color: readonly [number, number, number, number]): number => {
      const linear = (channel: number): number => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * linear(color[0]) + 0.7152 * linear(color[1]) + 0.0722 * linear(color[2]);
    };
    const background = (element: Element): readonly [number, number, number, number] | null => {
      let current: Element | null = element;
      while (current) {
        const color = rgb(getComputedStyle(current).backgroundColor);
        if (color && color[3] >= 0.99) return color;
        current = current.parentElement;
      }
      return null;
    };

    if (document.documentElement.lang !== "ko") {
      add("html-lang", document.documentElement, "The product document language must be Korean.");
    }
    if (!document.title.trim()) add("document-title", document.documentElement, "Missing title.");
    if (document.querySelectorAll("main").length !== 1) {
      add("single-main", document.body, "Expected exactly one main landmark.");
    }
    if (document.querySelectorAll("h1").length !== 1) {
      add("single-h1", document.body, "Expected exactly one page heading.");
    }

    const ids = new Set<string>();
    for (const element of document.querySelectorAll<HTMLElement>("[id]")) {
      if (ids.has(element.id)) add("unique-id", element, `Duplicate id ${element.id}.`);
      ids.add(element.id);
    }
    for (const element of document.querySelectorAll<HTMLElement>("[aria-describedby], [aria-labelledby]")) {
      for (const attribute of ["aria-describedby", "aria-labelledby"] as const) {
        const references = element.getAttribute(attribute)?.split(/\s+/u) ?? [];
        for (const reference of references) {
          if (reference && !document.getElementById(reference)) {
            add("valid-aria-reference", element, `${attribute} references missing #${reference}.`);
          }
        }
      }
    }

    const interactive = document.querySelectorAll<HTMLElement>(
      "a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=link]",
    );
    for (const element of interactive) {
      if (isVisible(element) && !accessibleName(element)) {
        add("accessible-name", element, "Visible interactive control has no accessible name.");
      }
      if (element.tabIndex > 0) add("tab-order", element, "Positive tabindex changes source order.");
      if (element.querySelector("a[href], button, input, select, textarea, [role=button], [role=link]")) {
        add("nested-interactive", element, "Interactive controls must not be nested.");
      }
    }
    for (const image of document.querySelectorAll("img")) {
      if (!image.hasAttribute("alt")) add("image-alt", image, "Image is missing alt.");
    }
    for (const frame of document.querySelectorAll("iframe")) {
      if (!frame.getAttribute("title")?.trim()) add("frame-title", frame, "Frame is missing title.");
    }
    for (const heading of document.querySelectorAll<HTMLElement>("h1, h2, h3")) {
      if (/[\uac00-\ud7a3]/u.test(heading.textContent ?? "") && getComputedStyle(heading).wordBreak !== "keep-all") {
        add("cjk-word-break", heading, "Korean headings must wrap at word boundaries before splitting glyphs.");
      }
    }
    for (const element of document.querySelectorAll<HTMLElement>("body *")) {
      const hasDirectText = [...element.childNodes].some(
        (node) => node.nodeType === Node.TEXT_NODE && Boolean(node.textContent?.trim()),
      );
      if (!hasDirectText || !isVisible(element) || element.matches(":disabled")) continue;
      const style = getComputedStyle(element);
      const foreground = rgb(style.color);
      const surface = background(element);
      if (!foreground || !surface) continue;
      const light = Math.max(luminance(foreground), luminance(surface));
      const dark = Math.min(luminance(foreground), luminance(surface));
      const ratio = (light + 0.05) / (dark + 0.05);
      const fontSize = Number.parseFloat(style.fontSize);
      const fontWeight = Number.parseInt(style.fontWeight, 10);
      const minimum = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700) ? 3 : 4.5;
      if (ratio < minimum) {
        add("color-contrast-aa", element, `Contrast ${ratio.toFixed(2)} is below ${minimum.toFixed(1)}.`);
      }
    }

    let previousLevel = 0;
    for (const heading of document.querySelectorAll("h1, h2, h3, h4, h5, h6")) {
      if (!isVisible(heading)) continue;
      const level = Number(heading.localName.slice(1));
      if (previousLevel && level > previousLevel + 1) {
        add("heading-order", heading, `Heading level jumps from h${previousLevel} to h${level}.`);
      }
      previousLevel = level;
    }
    const skipLink = document.querySelector<HTMLAnchorElement>('a[href="#main-content"]');
    if (!skipLink || !document.querySelector(skipLink.hash)) {
      add("skip-link", document.body, "Skip link is absent or targets a missing element.");
    }
    const currentPages = document.querySelectorAll('[aria-current="page"]');
    if (currentPages.length !== 1) {
      add("aria-current", document.body, `Expected one current page link, found ${currentPages.length}.`);
    }
    return violations;
  });
}

export async function scanTouchTargets(page: Page): Promise<readonly AccessibilityViolation[]> {
  return page.evaluate(() => {
    const violations: AccessibilityViolation[] = [];
    const controls = document.querySelectorAll<HTMLElement>(
      "a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=link]",
    );
    for (const element of controls) {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        box.width === 0 ||
        box.height === 0 ||
        element.matches(".skip-link")
      ) continue;
      if (box.width < 44 || box.height < 44) {
        const id = element.id ? `#${element.id}` : "";
        const classes = [...element.classList].map((name) => `.${name}`).join("");
        violations.push({
          detail: `Rendered target "${(element.textContent ?? "").trim().slice(0, 40)}" is ${box.width.toFixed(1)}x${box.height.toFixed(1)} CSS px.`,
          rule: "target-size-44",
          selector: `${element.localName}${id}${classes}`,
        });
      }
    }
    return violations;
  });
}
