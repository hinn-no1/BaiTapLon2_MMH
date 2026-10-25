async function getJson(path, body) {
  const options =
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        };
  const response = await fetch(path, options);
  const value = await response.json().catch(() => {
    throw new Error(`HTTP ${response.status}: phản hồi không phải JSON`);
  });
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}
function show(id, value) {
  const output = document.getElementById(id);
  if (!output) return;

  function format(item, depth = 0) {
    const indent = '  '.repeat(depth);
    const childIndent = '  '.repeat(depth + 1);

    if (typeof item === 'string') {
      const isPem =
        item.startsWith('-----BEGIN ') &&
        item.includes('-----END ');

      if (isPem) {
        return '\n' + item
          .trimEnd()
          .split(/\r?\n/)
          .map(line => childIndent + line)
          .join('\n');
      }

      return JSON.stringify(item);
    }

    if (Array.isArray(item)) {
      if (item.length === 0) return '[]';

      return '[\n' +
        item.map(entry =>
          childIndent + format(entry, depth + 1)
        ).join(',\n') +
        '\n' + indent + ']';
    }

    if (item !== null && typeof item === 'object') {
      const entries = Object.entries(item);
      if (entries.length === 0) return '{}';

      return '{\n' +
        entries.map(([key, entry]) =>
          childIndent +
          JSON.stringify(key) +
          ': ' +
          format(entry, depth + 1)
        ).join(',\n') +
        '\n' + indent + '}';
    }

    return JSON.stringify(item);
  }

  output.textContent = format(value);
}
async function action(id, fn) {
  try {
    await fn();
  } catch (err) {
    document.getElementById(id).textContent = `Lỗi: ${err.message}`;
  }
}
const payload = () => ({
  message: document.getElementById("message").value,
  algorithm: document.getElementById("algorithm").value,
});
document.getElementById("toy-dh").onclick = () =>
  action("toy-dh-out", async () =>
    show("toy-dh-out", await getJson("/api/toy-dh")),
  );
document.getElementById("ecdh").onclick = () =>
  action("ecdh-out", async () => show("ecdh-out", await getJson("/api/ecdh")));
document.getElementById("encrypt").onclick = () =>
  action("encrypt-out", async () =>
    show("encrypt-out", await getJson("/api/aead", payload())),
  );
document.getElementById("toy-ecdsa").onclick = () =>
  action("toy-ecdsa-out", async () =>
    show("toy-ecdsa-out", await getJson("/api/toy-ecdsa")),
  );
document.getElementById("bench").onclick = () =>
  action("bench-out", async () => {
    const value = await getJson("/api/benchmarks");
    show("bench-out", value);
    renderBenchmarks(value);
  });
document.getElementById("mitm").onclick = () =>
  action("mitm-out", async () => {
    const result = await getJson("/api/mitm", payload());
    const el = document.getElementById("mitm-out");
    el.replaceChildren();
    for (const mode of ["without_auth", "with_auth"]) {
      const section = document.createElement("div");
      section.className = "log";
      const title = document.createElement("h3");
      title.textContent =
        result[mode].mode +
        " — " +
        (result[mode].mitm_success ? "MITM thành công" : "MITM thất bại");
      title.className = result[mode].mitm_success ? "warn" : "ok";
      section.appendChild(title);
      const pre = document.createElement("pre");
      pre.textContent = result[mode].log.join("\n");
      section.appendChild(pre);
      const detail = document.createElement("pre");
      detail.textContent = JSON.stringify(
        Object.fromEntries(
          Object.entries(result[mode]).filter(([k]) => k !== "log"),
        ),
        null,
        2,
      );
      section.appendChild(detail);
      el.appendChild(section);
    }
  });

const labPayload = () => ({
  ...payload(),
  source: document.getElementById("source").value,
  signature_algorithm: document.getElementById("signature-algorithm").value,
});
document.getElementById("setup").onclick = () =>
  action("setup-out", async () => {
    const value = await getJson("/api/lab/setup", {
      alice: document.getElementById("alice-name").value,
      bob: document.getElementById("bob-name").value,
      ca: document.getElementById("ca-name").value,
      signature_algorithm: document.getElementById("signature-algorithm").value,
    });
    show("setup-out", value);
    for (const id of [
      "certificates-out",
      "check-certificate-out",
      "sign-out",
      "channel-out",
    ])
      document.getElementById(id).textContent = "";
    document.getElementById("downloads").hidden = true;
  });
document.getElementById("upload").onclick = () =>
  action("upload-out", async () => {
    const file = document.getElementById("data-file").files[0];
    if (!file) throw new Error("Hãy chọn một tệp");
    if (file.size > 10 * 1024 * 1024) throw new Error("Tệp tối đa 10 MiB");
    const form = new FormData();
    form.append("file", file);
    const response = await fetch("/api/lab/upload", {
      method: "POST",
      body: form,
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
    show("upload-out", value);
    document.getElementById("source").value = "file";
  });
document.getElementById("hash").onclick = () =>
  action("hash-out", async () =>
    show(
      "hash-out",
      await getJson("/api/lab/hash", {
        ...labPayload(),
        hmac_key: document.getElementById("hmac-key").value,
        hmac_tag: document.getElementById("hmac-tag").value,
      }),
    ),
  );
document.getElementById("sign").onclick = () =>
  action("sign-out", async () =>
    show("sign-out", await getJson("/api/lab/sign", labPayload())),
  );
document.getElementById("certificates").onclick = () =>
  action("certificates-out", async () =>
    show("certificates-out", await getJson("/api/lab/certificates", {})),
  );
document.getElementById("check-certificate").onclick = () =>
  action("check-certificate-out", async () =>
    show(
      "check-certificate-out",
      await getJson("/api/lab/check-certificate", {
        scenario: document.getElementById("cert-scenario").value,
      }),
    ),
  );
document.getElementById("channel").onclick = () =>
  action("channel-out", async () => {
    document.getElementById("downloads").hidden = true;
    const result = await getJson("/api/lab/channel", {
      ...labPayload(),
      mode: document.getElementById("mode").value,
    });
    show("channel-out", result);
    document.getElementById("downloads").hidden = false;
  });
document.getElementById("custom-dh").onclick = () =>
  action("custom-dh-out", async () => {
    const values = Object.fromEntries(
      ["p", "g", "a", "b"].map((k) => [
        k,
        Number(document.getElementById("dh-" + k).value),
      ]),
    );
    show("custom-dh-out", await getJson("/api/toy-dh", values));
  });
for (const button of document.querySelectorAll("[data-kerberos]")) {
  button.onclick = () =>
    action("kerberos-out", async () => {
      const value = await getJson("/api/kerberos/" + button.dataset.kerberos, {
        password: document.getElementById("kerberos-password").value,
      });
      document.getElementById("kerberos-log").textContent +=
        (value.ok ? "[CHẤP NHẬN] " : "[TỪ CHỐI] ") + value.message + "\n";
      show("kerberos-out", value);
    });
}
function renderBenchmarks(value) {
  const container = document.getElementById("bench-table");
  container.replaceChildren();
  const table = document.createElement("table");
  const head = document.createElement("thead"),
    row = document.createElement("tr");
  for (const label of [
    "Nhóm",
    "Thuật toán",
    "Thao tác",
    "Số lượt",
    "Trung bình (ms)",
    "Trung vị (ms)",
    "Khóa công khai / chữ ký (byte)",
  ]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    row.appendChild(cell);
  }
  head.appendChild(row);
  table.appendChild(head);
  const body = document.createElement("tbody");
  for (const group of ["signatures", "key_exchange", "aead"]) {
    for (const [algorithm, metrics] of Object.entries(value[group] || {})) {
      for (const [operation, result] of Object.entries(metrics)) {
        if (!result || typeof result !== "object" || !("mean_ms" in result))
          continue;
        const tr = document.createElement("tr");
        for (const item of [
          group,
          algorithm,
          operation,
          result.runs,
          result.mean_ms,
          result.median_ms,
          group === "signatures"
            ? `${metrics.public_key_pem_bytes} / ${metrics.signature_bytes}`
            : "—",
        ]) {
          const td = document.createElement("td");
          td.textContent = String(item);
          tr.appendChild(td);
        }
        body.appendChild(tr);
      }
    }
  }
    table.appendChild(body);
  container.appendChild(table);
}

(function () {
  function initFunctionMenu() {
      if (document.getElementById("function-menu")) return;

      const panels = Array.from(document.querySelectorAll("main > section"));

      const labels = [
        "1. Sinh khóa",
        "2. Băm & chữ ký",
        "3. Chứng thư",
        "4. Kênh truyền",
        "5. Thử nghiệm",
        "6. Benchmark",
        "7. Kerberos",
      ];

      if (panels.length !== labels.length) {
        console.warn("Không tìm thấy đủ 7 phần chức năng.");
        return;
      }

      const menu = document.createElement("nav");
      menu.id = "function-menu";
      menu.setAttribute("aria-label", "Chọn chức năng");

      const menuItems = document.createElement("div");
      menuItems.className = "function-menu-items";
      menu.appendChild(menuItems);

      const buttons = [];

      function selectPanel(index, userAction = false) {
        panels.forEach((panel, position) => {
          const selected = position === index;

          panel.hidden = !selected;

          buttons[position].classList.toggle("is-active", selected);
          buttons[position].setAttribute("aria-pressed", String(selected));
        });
        const selectedButton = buttons[index];

        menuItems.scrollTo({
          left:
            selectedButton.offsetLeft -
            (menuItems.clientWidth - selectedButton.offsetWidth) / 2,
          behavior: "auto",
        });

        if (userAction) {
          window.scrollTo({
            top: 0,
            behavior: "auto",
          });
        }
      }

      panels.forEach((panel, index) => {
        if (!panel.id) {
          panel.id = `function-panel-${index + 1}`;
        }

        const button = document.createElement("button");
        button.type = "button";
        button.className = "function-menu-button";
        button.textContent = labels[index];

        button.setAttribute("aria-controls", panel.id);
        button.setAttribute("aria-pressed", "false");

        button.addEventListener("click", () => {
          selectPanel(index, true);
        });

        buttons.push(button);
        menuItems.appendChild(button);
      });
      document.body.prepend(menu);
      selectPanel(0);
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initFunctionMenu, {
        once: true,
      });
    } else {
      initFunctionMenu();
    }
  })();
