/* SecureCode AI — Frontend (Groq-powered, Dark/Light mode, Streaming Chat) */

const API_BASE = '';

// ─── DOM references ──────────────────────────────────────────────────────────
const codeEditor         = document.getElementById('code-editor');
const lineNumbers        = document.getElementById('line-numbers');
const codeStatus         = document.getElementById('code-status');
const codeTab            = document.getElementById('code-tab');
const uploadTab          = document.getElementById('upload-tab');
const editorPanel        = document.getElementById('editor-panel');
const uploadPanel        = document.getElementById('upload-panel');
const sampleBtn          = document.getElementById('sample-btn');
const clearCodeBtn       = document.getElementById('clear-code-btn');
const sourceName         = document.getElementById('source-name');
const detectedLanguage   = document.getElementById('detected-language');
const editorTitle        = document.getElementById('editor-title');
const dropZone           = document.getElementById('drop-zone');
const fileInput          = document.getElementById('file-input');
const projectInput       = document.getElementById('project-input');
const browseProjectBtn   = document.getElementById('browse-project-btn');
const browseBtn          = document.getElementById('browse-btn');
const repoUrlInput       = document.getElementById('repo-url-input');
const repoBranchInput    = document.getElementById('repo-branch-input');
const analyzeRepoBtn     = document.getElementById('analyze-repo-btn');
const browseZipBtn       = document.getElementById('browse-zip-btn');
const projectZipInput    = document.getElementById('project-zip-input');
const clearBtn           = document.getElementById('clear-btn');
const filePreview        = document.getElementById('file-preview');
const fileNameEl         = document.getElementById('file-name');
const fileSizeEl         = document.getElementById('file-size');
const analyzeBtn         = document.getElementById('analyze-btn');
const btnText            = analyzeBtn.querySelector('.btn-text');
const btnSpinner         = analyzeBtn.querySelector('.btn-spinner');
const resultsSection     = document.getElementById('results-section');
const errorCard          = document.getElementById('error-card');
const errorMsg           = document.getElementById('error-msg');
const summaryBar         = document.getElementById('summary-bar');
const vulnSection        = document.getElementById('vuln-section');
const vulnList           = document.getElementById('vuln-list');
const symbolSection      = document.getElementById('symbol-section');
const symbolBody         = document.getElementById('symbol-body');
const symbolWrap         = document.getElementById('symbol-table-wrap');
const toggleSymbol       = document.getElementById('toggle-symbol-btn');
const statsSection       = document.getElementById('stats-section');
const statsGrid          = document.getElementById('stats-grid');
const projectGraphSection= document.getElementById('project-graph-section');
const projectGraphSummary= document.getElementById('project-graph-summary');
const projectGraphDetails= document.getElementById('project-graph-details');
const explorerFileList   = document.getElementById('explorer-file-list');
const explorerProjectTitle = document.getElementById('explorer-project-title');
const explorerStatus     = document.getElementById('explorer-status');
const paneSplitter       = document.getElementById('pane-splitter');
const themeToggle        = document.getElementById('theme-toggle');
const modelSelect        = document.getElementById('model-select');
const aiStatusPill       = document.getElementById('ai-model-status');
const aiStatusText       = aiStatusPill.querySelector('.status-text');
const reportToolbar      = document.getElementById('report-toolbar');

let explorerEntries      = [];
let projectEdits         = new Map();
let selectedProjectPath  = null;
let currentSingleFile    = null;
let currentAnalysisData  = null;
let currentAnalysisCode  = '';
let aiRepairResult       = null;
let currentFilter        = 'all';
let uploadedFilename     = 'pasted_code.txt';
let projectFiles         = null;
let projectZipFile       = null;
let projectFilesMap      = new Map(); // relPath -> { path, name, file, content }
let projectTreeRoot      = null;      // ProjectTreeNode root
let projectSearchQuery   = '';
let openEditorTabs       = new Map(); // path -> { path, name, content, language, isDirty }
let activeEditorTabPath  = null;
let fullProjectAnalysisData = null;

const EXTENSIONS = { Python: '.py', JavaScript: '.js', Java: '.java', C: '.c', 'C++': '.cpp' };
const SAMPLES = {
  python: `from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

@app.route('/search')
def search():
    name = request.args.get('name')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    return str(cursor.fetchall())

@app.route('/run')
def run():
    command = request.args.get('cmd')
    os.system(command)
    return 'done'
`,
  javascript: `const express = require('express');
const { exec } = require('child_process');
app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd);
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id=" + id);
});`,
  java: `import java.sql.*;
class Demo {
  void search(String user) throws Exception {
    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM users WHERE name='" + user + "'");
    Runtime.getRuntime().exec(user);
  }
}`,
  c: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void run(char *input) {
  char buf[32];
  strcpy(buf, input);
  system(input);
}`,
  cpp: `#include <cstdlib>
#include <cstring>
void run(const char* input) {
  char buf[32];
  strcpy(buf, input);
  system(input);
}`
};

// ─── Dark / Light mode ───────────────────────────────────────────────────────
function getStoredTheme() {
  try { return localStorage.getItem('securecode-theme') || 'light'; } catch { return 'light'; }
}
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('securecode-theme', theme); } catch {}
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  setTheme(current === 'dark' ? 'light' : 'dark');
}
// Apply saved theme immediately
setTheme(getStoredTheme());
themeToggle.addEventListener('click', toggleTheme);

// ─── Language detection ──────────────────────────────────────────────────────
function syntaxDetectLanguage(code, filename = '') {
  const name = (filename || '').toLowerCase();
  const extMap = { '.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.java': 'Java', '.c': 'C', '.h': 'C', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++', '.hpp': 'C++', '.hh': 'C++' };
  const matchedExt = Object.keys(extMap).find(ext => name.endsWith(ext));
  if (matchedExt) return { language: extMap[matchedExt], confidence: 1.0, method: 'file extension' };
  const scores = { Python: 0, JavaScript: 0, Java: 0, C: 0, 'C++': 0 };
  const add = (lang, re, weight) => { if (re.test(code)) scores[lang] += weight; };
  add('Python', /^\s*(from|import)\s+\w+/m, 3); add('Python', /^\s*def\s+\w+\s*\(/m, 3); add('Python', /\b(None|elif|True|False)\b/, 1);
  add('JavaScript', /\b(const|let|var)\s+[A-Za-z_$]/, 2); add('JavaScript', /=>/, 2); add('JavaScript', /\b(require|module\.exports|console\.)/, 2);
  add('Java', /^\s*package\s+[^;]+;/m, 3); add('Java', /^\s*import\s+[^;]+;/m, 2); add('Java', /\bpublic\s+class\s+\w+/, 3);
  add('C++', /#\s*include\s*<iostream>/, 3); add('C++', /\bstd::|cout|cin/, 2.5);
  add('C', /#\s*include\s*<(stdio|stdlib|string|unistd)\.h>/, 3); add('C', /\b(printf|scanf|malloc|free|strcpy)\s*\(/, 1.5);
  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  if (!ranked[0][1]) return { language: 'Unknown', confidence: 0, method: 'not enough syntax evidence' };
  const best = ranked[0][0], second = ranked[1][1];
  const confidence = Math.min(0.99, 0.55 + Math.min(ranked[0][1], 10) / 20 + Math.min(Math.max(ranked[0][1] - second, 0), 5) / 20);
  return { language: best, confidence, method: 'source syntax' };
}

function updateLanguageUI() {
  const result = syntaxDetectLanguage(codeEditor.value, sourceName.value);
  const lang = result.language;
  detectedLanguage.textContent = lang === 'Unknown' ? 'Unknown — add a file extension' : `${lang} · ${Math.round(result.confidence * 100)}% confidence`;
  editorTitle.textContent = lang === 'Unknown' ? 'Source code' : `${lang} source`;
  codeEditor.placeholder = SAMPLES[lang === 'C++' ? 'cpp' : (lang || 'python').toLowerCase()] || SAMPLES.python;
}
sourceName.addEventListener('input', updateLanguageUI);

// ─── Code editor ─────────────────────────────────────────────────────────────
function updateEditorState() {
  const code = codeEditor.value;
  const lines = Math.max(1, code.split('\n').length);
  lineNumbers.textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
  codeStatus.textContent = `${lines} line${lines === 1 ? '' : 's'} · ${code.length} characters`;
  analyzeBtn.disabled = !code.trim() && !projectFiles && !projectZipFile;
  updateLanguageUI();
}
codeEditor.addEventListener('input', updateEditorState);
codeEditor.addEventListener('scroll', () => { lineNumbers.scrollTop = codeEditor.scrollTop; });
codeEditor.addEventListener('input', () => {
  if (activeEditorTabPath && openEditorTabs.has(activeEditorTabPath)) {
    const tab = openEditorTabs.get(activeEditorTabPath);
    if (!tab.isDirty && tab.content !== codeEditor.value) {
      tab.isDirty = true;
      renderEditorTabs();
    }
    projectEdits.set(activeEditorTabPath, codeEditor.value);
  } else if (selectedProjectPath) {
    projectEdits.set(selectedProjectPath, codeEditor.value);
  }
});

// ─── VS Code Tree Model & File Explorer System (Feature 14) ─────────────────
class ProjectTreeNode {
  constructor(name, path, isDir = false) {
    this.name = name;
    this.path = path;
    this.isDir = isDir;
    this.children = new Map();
    this.expanded = true;
    this.checked = true;
    this.indeterminate = false;
    this.fileObj = null;
    this.content = null;
    this.findingsCount = 0;
  }
}

function getFileIcon(filename) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  switch (ext) {
    case 'py':
    case 'pyw':
      return { icon: '🐍', color: '#38bdf8' };
    case 'js':
    case 'mjs':
    case 'jsx':
    case 'cjs':
      return { icon: '🟨', color: '#facc15' };
    case 'java':
      return { icon: '☕', color: '#ea580c' };
    case 'c':
    case 'h':
      return { icon: 'Ⓒ', color: '#60a5fa' };
    case 'cpp':
    case 'cc':
    case 'cxx':
    case 'hpp':
    case 'hh':
      return { icon: '➕', color: '#a855f7' };
    case 'json':
      return { icon: '{}', color: '#fbbf24' };
    case 'md':
    case 'txt':
      return { icon: '📄', color: '#94a3b8' };
    case 'html':
      return { icon: '🌐', color: '#f97316' };
    case 'css':
      return { icon: '🎨', color: '#38bdf8' };
    case 'yml':
    case 'yaml':
    case 'toml':
    case 'env':
      return { icon: '⚙️', color: '#e2e8f0' };
    default:
      return { icon: '📝', color: '#94a3b8' };
  }
}

function buildProjectTree(filesMap, rootTitle = 'PROJECT') {
  const root = new ProjectTreeNode(rootTitle, '', true);
  for (const [relPath, item] of filesMap.entries()) {
    const parts = relPath.replace(/\\/g, '/').split('/').filter(Boolean);
    let curr = root;
    let currPath = '';
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      currPath = currPath ? `${currPath}/${part}` : part;
      const isLast = (i === parts.length - 1);
      if (isLast) {
        const fileNode = new ProjectTreeNode(part, currPath, false);
        fileNode.fileObj = item.file || null;
        fileNode.content = item.content || null;
        curr.children.set(part, fileNode);
      } else {
        if (!curr.children.has(part)) {
          curr.children.set(part, new ProjectTreeNode(part, currPath, true));
        }
        curr = curr.children.get(part);
      }
    }
  }
  return root;
}

function setNodeCheckedRecursive(node, isChecked) {
  if (!node) return;
  node.checked = isChecked;
  node.indeterminate = false;
  if (node.isDir) {
    for (const child of node.children.values()) {
      setNodeCheckedRecursive(child, isChecked);
    }
  }
}

function updateTreeCheckedState(node) {
  if (!node || !node.isDir) return;
  let allChecked = true;
  let noneChecked = true;
  let hasIndeterminate = false;

  for (const child of node.children.values()) {
    if (child.isDir) {
      updateTreeCheckedState(child);
    }
    if (child.checked) {
      noneChecked = false;
    } else {
      allChecked = false;
    }
    if (child.indeterminate) {
      hasIndeterminate = true;
      noneChecked = false;
      allChecked = false;
    }
  }

  if (allChecked) {
    node.checked = true;
    node.indeterminate = false;
  } else if (noneChecked) {
    node.checked = false;
    node.indeterminate = false;
  } else {
    node.checked = false;
    node.indeterminate = true;
  }
}

function getSelectedFiles(node, result = []) {
  if (!node) return result;
  if (!node.isDir) {
    if (node.checked) result.push(node);
  } else {
    for (const child of node.children.values()) {
      getSelectedFiles(child, result);
    }
  }
  return result;
}

function getFolderFiles(dirNode, result = []) {
  if (!dirNode) return result;
  for (const child of dirNode.children.values()) {
    if (child.isDir) getFolderFiles(child, result);
    else result.push(child);
  }
  return result;
}

function countTreeFilesAndFolders(node) {
  let files = 0;
  let folders = 0;
  let selected = 0;
  function traverse(n) {
    if (!n) return;
    if (n !== node && n.isDir) folders++;
    if (!n.isDir) {
      files++;
      if (n.checked) selected++;
    }
    for (const child of n.children.values()) traverse(child);
  }
  traverse(node);
  return { files, folders, selected };
}

function doesNodeMatchSearch(node, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  if (node.name.toLowerCase().includes(q) || node.path.toLowerCase().includes(q)) return true;
  if (node.isDir) {
    for (const child of node.children.values()) {
      if (doesNodeMatchSearch(child, query)) return true;
    }
  }
  return false;
}

function updateSelectionToolbar() {
  const selectionBar = document.getElementById('explorer-selection-bar');
  const countEl = document.getElementById('explorer-selection-count');
  const selectAllChk = document.getElementById('explorer-select-all');
  const countsBadge = document.getElementById('explorer-counts');
  const scanSelectedBtn = document.getElementById('explorer-scan-selected');

  if (!projectTreeRoot || projectFilesMap.size === 0) {
    if (selectionBar) selectionBar.style.display = 'none';
    if (countsBadge) countsBadge.style.display = 'none';
    return;
  }

  if (selectionBar) selectionBar.style.display = 'flex';
  const { files, folders, selected } = countTreeFilesAndFolders(projectTreeRoot);

  if (countEl) countEl.textContent = `Selected: ${selected} / ${files}`;
  if (countsBadge) {
    countsBadge.style.display = 'inline-block';
    countsBadge.textContent = `${files} files · ${folders} folders`;
  }

  if (selectAllChk) {
    selectAllChk.checked = (selected === files && files > 0);
    selectAllChk.indeterminate = (selected > 0 && selected < files);
  }

  if (scanSelectedBtn) {
    scanSelectedBtn.textContent = `⚡ Scan Selected (${selected})`;
    scanSelectedBtn.disabled = (selected === 0);
  }
}

function renderProjectExplorer() {
  if (!explorerFileList) return;
  explorerFileList.innerHTML = '';

  if (!projectTreeRoot || projectFilesMap.size === 0) {
    explorerFileList.innerHTML = '<div class="explorer-empty">Open a file, folder, ZIP, or GitHub repository to see files here.</div>';
    updateSelectionToolbar();
    return;
  }

  const query = (projectSearchQuery || '').trim();
  renderTreeDOM(projectTreeRoot, explorerFileList, 0, query);
  updateSelectionToolbar();
}

function renderTreeDOM(node, container, depth = 0, query = '') {
  const children = Array.from(node.children.values()).sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  for (const child of children) {
    const matches = doesNodeMatchSearch(child, query);
    if (!matches) continue;

    const nodeEl = document.createElement('div');
    nodeEl.className = 'tree-node';

    const rowEl = document.createElement('div');
    rowEl.className = 'tree-row' + (child.path === activeEditorTabPath ? ' active' : '');
    rowEl.style.paddingLeft = `${depth * 14 + 6}px`;
    rowEl.title = child.path;

    if (child.isDir) {
      const chevron = document.createElement('span');
      chevron.className = 'tree-chevron' + (child.expanded ? '' : ' collapsed');
      chevron.textContent = child.expanded ? '▾' : '▸';
      chevron.onclick = (e) => {
        e.stopPropagation();
        child.expanded = !child.expanded;
        renderProjectExplorer();
      };
      rowEl.appendChild(chevron);

      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.className = 'tree-checkbox';
      chk.checked = child.checked;
      chk.indeterminate = child.indeterminate;
      chk.onclick = (e) => {
        e.stopPropagation();
        setNodeCheckedRecursive(child, chk.checked);
        updateTreeCheckedState(projectTreeRoot);
        updateSelectionToolbar();
        renderProjectExplorer();
      };
      rowEl.appendChild(chk);

      const icon = document.createElement('span');
      icon.className = 'tree-icon';
      icon.textContent = child.expanded ? '📂' : '📁';
      rowEl.appendChild(icon);

      const label = document.createElement('span');
      label.className = 'tree-label';
      label.textContent = child.name;
      rowEl.appendChild(label);

      const childCount = getFolderFiles(child).length;
      const badge = document.createElement('span');
      badge.className = 'tree-badge';
      badge.textContent = childCount;
      rowEl.appendChild(badge);

      const scanFolderBtn = document.createElement('button');
      scanFolderBtn.type = 'button';
      scanFolderBtn.className = 'tree-folder-action';
      scanFolderBtn.title = `Analyse folder "${child.name}"`;
      scanFolderBtn.textContent = '⚡ Scan';
      scanFolderBtn.onclick = (e) => {
        e.stopPropagation();
        runSelectiveAnalysis('folder', child);
      };
      rowEl.appendChild(scanFolderBtn);

      rowEl.onclick = () => {
        child.expanded = !child.expanded;
        renderProjectExplorer();
      };

      nodeEl.appendChild(rowEl);

      const childrenContainer = document.createElement('div');
      childrenContainer.className = 'tree-children' + (child.expanded ? '' : ' collapsed');
      renderTreeDOM(child, childrenContainer, depth + 1, query);
      nodeEl.appendChild(childrenContainer);

    } else {
      const spacer = document.createElement('span');
      spacer.className = 'tree-chevron';
      rowEl.appendChild(spacer);

      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.className = 'tree-checkbox';
      chk.checked = child.checked;
      chk.indeterminate = false;
      chk.onclick = (e) => {
        e.stopPropagation();
        child.checked = chk.checked;
        updateTreeCheckedState(projectTreeRoot);
        updateSelectionToolbar();
        renderProjectExplorer();
      };
      rowEl.appendChild(chk);

      const fileInfo = getFileIcon(child.name);
      const icon = document.createElement('span');
      icon.className = 'tree-icon';
      icon.textContent = fileInfo.icon;
      rowEl.appendChild(icon);

      const label = document.createElement('span');
      label.className = 'tree-label';
      label.textContent = child.name;
      rowEl.appendChild(label);

      if (child.findingsCount > 0) {
        const vulnBadge = document.createElement('span');
        vulnBadge.className = 'tree-badge';
        vulnBadge.textContent = `${child.findingsCount} ⚠`;
        rowEl.appendChild(vulnBadge);
      }

      rowEl.onclick = async () => {
        await openFileInTab(child.path, child.fileObj, child.content);
      };

      nodeEl.appendChild(rowEl);
    }

    container.appendChild(nodeEl);
  }
}

function renderExplorer(entries, title = 'PROJECT') {
  if (explorerProjectTitle) explorerProjectTitle.textContent = title;
  if (!entries || !entries.length) {
    projectFilesMap.clear();
    projectTreeRoot = null;
    openEditorTabs.clear();
    activeEditorTabPath = null;
    renderProjectExplorer();
    renderEditorTabs();
    return;
  }

  entries.forEach(e => {
    const p = e.path || e.name;
    if (p) {
      if (!projectFilesMap.has(p)) {
        projectFilesMap.set(p, {
          path: p,
          name: p.split('/').pop(),
          file: e.file || null,
          content: e.content || null
        });
      } else {
        const item = projectFilesMap.get(p);
        if (e.file && !item.file) item.file = e.file;
        if (e.content !== undefined && e.content !== null) item.content = e.content;
      }
    }
  });

  projectTreeRoot = buildProjectTree(projectFilesMap, title);
  renderProjectExplorer();
}

// ─── VS Code Editor Tabs & Breadcrumbs ──────────────────────────────────────
function renderEditorTabs() {
  const tabsBar = document.getElementById('editor-tabs-bar');
  if (!tabsBar) return;
  tabsBar.innerHTML = '';

  if (openEditorTabs.size === 0) {
    tabsBar.style.display = 'none';
    updateBreadcrumbs('');
    return;
  }
  tabsBar.style.display = 'flex';

  for (const [path, tab] of openEditorTabs.entries()) {
    const tabEl = document.createElement('div');
    const isActive = (path === activeEditorTabPath);
    tabEl.className = 'editor-tab' + (isActive ? ' editor-tab--active' : '') + (tab.isDirty ? ' dirty' : '');
    tabEl.title = path;

    const fileInfo = getFileIcon(tab.name);
    const icon = document.createElement('span');
    icon.className = 'tab-icon';
    icon.textContent = fileInfo.icon;

    const title = document.createElement('span');
    title.className = 'tab-title';
    title.textContent = tab.name;

    const dirtyDot = document.createElement('span');
    dirtyDot.className = 'tab-dirty';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tab-close';
    closeBtn.textContent = '×';
    closeBtn.title = 'Close tab';
    closeBtn.onclick = (e) => {
      e.stopPropagation();
      closeEditorTab(path);
    };

    tabEl.appendChild(icon);
    tabEl.appendChild(title);
    tabEl.appendChild(dirtyDot);
    tabEl.appendChild(closeBtn);

    tabEl.onclick = () => {
      activateEditorTab(path);
    };

    tabsBar.appendChild(tabEl);
  }

  const activeTabEl = tabsBar.querySelector('.editor-tab--active');
  if (activeTabEl) activeTabEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
  setTimeout(() => { if (typeof updateSliderFromScroll === 'function') updateSliderFromScroll(); }, 100);

  updateBreadcrumbs(activeEditorTabPath);
}

function updateBreadcrumbs(filePath) {
  const breadcrumbs = document.getElementById('editor-breadcrumbs');
  if (!breadcrumbs) return;

  if (!filePath) {
    breadcrumbs.innerHTML = '<span class="breadcrumb-item breadcrumb-root">📁 No file selected</span>';
    return;
  }

  const parts = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
  const projectName = explorerProjectTitle?.textContent || 'PROJECT';
  let html = `<span class="breadcrumb-item breadcrumb-root">📁 ${escHtml(projectName)}</span>`;

  let currentPath = '';
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const isLast = (i === parts.length - 1);
    currentPath = currentPath ? `${currentPath}/${part}` : part;
    const icon = isLast ? getFileIcon(part).icon : '📁';
    html += ` <span class="breadcrumb-sep">›</span> <span class="breadcrumb-item">${icon} ${escHtml(part)}</span>`;
  }
  breadcrumbs.innerHTML = html;
}

async function openFileInTab(path, fileObj = null, optionalContent = null) {
  if (!path) return;

  if (activeEditorTabPath && openEditorTabs.has(activeEditorTabPath)) {
    const currTab = openEditorTabs.get(activeEditorTabPath);
    if (codeEditor.value !== currTab.content) {
      currTab.content = codeEditor.value;
      currTab.isDirty = true;
      projectEdits.set(activeEditorTabPath, codeEditor.value);
    }
  }

  if (!openEditorTabs.has(path)) {
    let content = '';
    if (projectEdits.has(path)) {
      content = projectEdits.get(path);
    } else if (optionalContent !== null && optionalContent !== undefined) {
      content = optionalContent;
    } else if (fileObj) {
      try {
        content = await fileObj.text();
      } catch (err) {
        showToast(`Could not read ${path}: ${err.message}`, 'error');
        return;
      }
    } else if (projectFilesMap.has(path)) {
      const item = projectFilesMap.get(path);
      if (item.content) {
        content = item.content;
      } else if (item.file) {
        try { content = await item.file.text(); }
        catch (err) { showToast(`Could not read ${path}: ${err.message}`, 'error'); return; }
      }
    } else if (currentAnalysisData && currentAnalysisData.file_sources && currentAnalysisData.file_sources[path]) {
      content = currentAnalysisData.file_sources[path];
    }

    const name = path.split('/').pop();
    openEditorTabs.set(path, {
      path,
      name,
      content,
      isDirty: false
    });
  }

  activateEditorTab(path);
}

function activateEditorTab(path) {
  if (!openEditorTabs.has(path)) return;

  activeEditorTabPath = path;
  selectedProjectPath = path;
  const tab = openEditorTabs.get(path);

  codeEditor.value = tab.content;
  sourceName.value = path;
  uploadedFilename = path;

  updateEditorState();
  switchTab('editor');
  renderEditorTabs();
  renderProjectExplorer();

  if (currentAnalysisData && currentAnalysisData.project && Array.isArray(currentAnalysisData.vulnerabilities)) {
    showFileFindingsFromProject(path);
  }
}

function closeEditorTab(path) {
  if (!openEditorTabs.has(path)) return;
  openEditorTabs.delete(path);

  if (activeEditorTabPath === path) {
    const remaining = Array.from(openEditorTabs.keys());
    if (remaining.length > 0) {
      activateEditorTab(remaining[remaining.length - 1]);
    } else {
      activeEditorTabPath = null;
      selectedProjectPath = null;
      codeEditor.value = '';
      sourceName.value = 'untitled.py';
      updateEditorState();
      renderEditorTabs();
      renderProjectExplorer();
    }
  } else {
    renderEditorTabs();
  }
}

async function navigateToLine(filePath, lineNumber) {
  if (!filePath && activeEditorTabPath) filePath = activeEditorTabPath;
  if (!filePath && sourceName) filePath = sourceName.value;
  if (!filePath) return;

  let targetPath = filePath.replace(/\\/g, '/');
  if (!openEditorTabs.has(targetPath) && !projectFilesMap.has(targetPath)) {
    for (const key of projectFilesMap.keys()) {
      if (key === targetPath || key.endsWith('/' + targetPath) || targetPath.endsWith('/' + key)) {
        targetPath = key;
        break;
      }
    }
  }

  await openFileInTab(targetPath);

  if (lineNumber && lineNumber > 0) {
    const lines = codeEditor.value.split('\n');
    let charOffset = 0;
    for (let i = 0; i < Math.min(lineNumber - 1, lines.length); i++) {
      charOffset += lines[i].length + 1;
    }
    const lineEnd = charOffset + (lines[lineNumber - 1] ? lines[lineNumber - 1].length : 0);

    codeEditor.focus();
    codeEditor.setSelectionRange(charOffset, lineEnd);

    const approxLineHeight = 19;
    const targetScroll = Math.max(0, (lineNumber - 5) * approxLineHeight);
    codeEditor.scrollTop = targetScroll;
    lineNumbers.scrollTop = targetScroll;

    codeEditor.classList.remove('line-highlight');
    void codeEditor.offsetWidth;
    codeEditor.classList.add('line-highlight');
    setTimeout(() => { codeEditor.classList.remove('line-highlight'); }, 2500);

    showToast(`Jumped to ${targetPath}:${lineNumber}`, 'info');
  }
}

// ─── Explorer Toolbar & Splitter Listeners ──────────────────────────────────
document.getElementById('explorer-open-file')?.addEventListener('click', () => { fileInput?.click(); });
document.getElementById('explorer-open-folder')?.addEventListener('click', () => { projectInput?.click(); });
document.getElementById('explorer-open-zip')?.addEventListener('click', () => { projectZipInput?.click(); });

// ─── Down-of-Editor Slider Controls ─────────────────────────────────────────
const editorHSlider = document.getElementById('editor-h-slider');
const sliderScrollLeft = document.getElementById('slider-scroll-left');
const sliderScrollRight = document.getElementById('slider-scroll-right');
const tabsBarEl = document.getElementById('editor-tabs-bar');

function updateSliderFromScroll() {
  if (!editorHSlider) return;
  const target = (tabsBarEl && tabsBarEl.scrollWidth > tabsBarEl.clientWidth) ? tabsBarEl : codeEditor;
  const maxScroll = Math.max(1, target.scrollWidth - target.clientWidth);
  const pct = Math.min(100, Math.max(0, (target.scrollLeft / maxScroll) * 100));
  editorHSlider.value = pct;
}

if (editorHSlider) {
  editorHSlider.addEventListener('input', () => {
    const pct = parseFloat(editorHSlider.value) / 100;
    if (tabsBarEl && tabsBarEl.scrollWidth > tabsBarEl.clientWidth) {
      tabsBarEl.scrollLeft = pct * (tabsBarEl.scrollWidth - tabsBarEl.clientWidth);
    }
    if (codeEditor && codeEditor.scrollWidth > codeEditor.clientWidth) {
      codeEditor.scrollLeft = pct * (codeEditor.scrollWidth - codeEditor.clientWidth);
    }
  });
}

if (sliderScrollLeft) {
  sliderScrollLeft.addEventListener('click', () => {
    if (tabsBarEl && tabsBarEl.scrollWidth > tabsBarEl.clientWidth) {
      tabsBarEl.scrollBy({ left: -80, behavior: 'smooth' });
    }
    if (codeEditor && codeEditor.scrollWidth > codeEditor.clientWidth) {
      codeEditor.scrollBy({ left: -80, behavior: 'smooth' });
    }
    setTimeout(updateSliderFromScroll, 200);
  });
}

if (sliderScrollRight) {
  sliderScrollRight.addEventListener('click', () => {
    if (tabsBarEl && tabsBarEl.scrollWidth > tabsBarEl.clientWidth) {
      tabsBarEl.scrollBy({ left: 80, behavior: 'smooth' });
    }
    if (codeEditor && codeEditor.scrollWidth > codeEditor.clientWidth) {
      codeEditor.scrollBy({ left: 80, behavior: 'smooth' });
    }
    setTimeout(updateSliderFromScroll, 200);
  });
}

if (tabsBarEl) {
  tabsBarEl.addEventListener('scroll', updateSliderFromScroll);
  tabsBarEl.addEventListener('wheel', (e) => {
    if (e.deltaY !== 0) {
      e.preventDefault();
      tabsBarEl.scrollLeft += e.deltaY;
      updateSliderFromScroll();
    }
  }, { passive: false });
}

if (codeEditor) {
  codeEditor.addEventListener('scroll', updateSliderFromScroll);
}
document.getElementById('collapse-explorer-btn')?.addEventListener('click', () => {
  document.body.classList.toggle('explorer-collapsed');
  const btn = document.getElementById('collapse-explorer-btn');
  if (btn) btn.textContent = document.body.classList.contains('explorer-collapsed') ? '›' : '‹';
});

// Left Splitter Resize Dragging
const explorerSplitterEl = document.getElementById('explorer-splitter');
const ideLayoutContainer = document.getElementById('ide-layout');

if (explorerSplitterEl && ideLayoutContainer) {
  let isDraggingExplorer = false;

  explorerSplitterEl.addEventListener('mousedown', (e) => {
    isDraggingExplorer = true;
    explorerSplitterEl.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });

  window.addEventListener('mousemove', (e) => {
    if (!isDraggingExplorer) return;
    const newWidth = Math.max(160, Math.min(600, e.clientX));
    ideLayoutContainer.style.setProperty('--explorer-width', `${newWidth}px`);
  });

  window.addEventListener('mouseup', () => {
    if (isDraggingExplorer) {
      isDraggingExplorer = false;
      explorerSplitterEl.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  });
}

// Search Filter Input
const searchInputEl = document.getElementById('explorer-search');
const searchClearBtnEl = document.getElementById('explorer-search-clear');

if (searchInputEl) {
  searchInputEl.addEventListener('input', () => {
    projectSearchQuery = searchInputEl.value;
    if (searchClearBtnEl) searchClearBtnEl.style.display = projectSearchQuery ? 'inline-block' : 'none';
    renderProjectExplorer();
  });
}

if (searchClearBtnEl) {
  searchClearBtnEl.addEventListener('click', () => {
    if (searchInputEl) searchInputEl.value = '';
    projectSearchQuery = '';
    searchClearBtnEl.style.display = 'none';
    renderProjectExplorer();
  });
}

// ─── Selective Analysis Integration (Feature 14) ───────────────────────────
function updateTreeFindings(data) {
  if (!projectTreeRoot || !data) return;

  function resetCounts(node) {
    if (!node) return;
    node.findingsCount = 0;
    for (const child of node.children.values()) resetCounts(child);
  }
  resetCounts(projectTreeRoot);

  if (Array.isArray(data.vulnerabilities)) {
    const countsByFile = new Map();
    for (const v of data.vulnerabilities) {
      const f = (v.file || data.filename || '').replace(/\\/g, '/');
      if (f) countsByFile.set(f, (countsByFile.get(f) || 0) + 1);
    }

    function applyCounts(node) {
      if (!node) return;
      if (!node.isDir) {
        for (const [fPath, cnt] of countsByFile.entries()) {
          if (node.path === fPath || node.path.endsWith('/' + fPath) || fPath.endsWith('/' + node.path)) {
            node.findingsCount = cnt;
            break;
          }
        }
      }
      for (const child of node.children.values()) applyCounts(child);
    }
    applyCounts(projectTreeRoot);
  }
  renderProjectExplorer();
}

async function runSelectiveAnalysis(mode = 'selected', folderNode = null) {
  let targetNodes = [];
  let scanLabel = '';

  if (mode === 'folder' && folderNode) {
    targetNodes = getFolderFiles(folderNode).filter(n => isSupportedSource(n.name));
    scanLabel = `folder "${folderNode.name}" (${targetNodes.length} file${targetNodes.length === 1 ? '' : 's'})`;
  } else if (mode === 'selected') {
    targetNodes = getSelectedFiles(projectTreeRoot).filter(n => isSupportedSource(n.name));
    scanLabel = `selected files (${targetNodes.length} file${targetNodes.length === 1 ? '' : 's'})`;
  } else if (mode === 'all') {
    if (projectZipFile) {
      sourceName.value = 'project.zip';
      return runAnalysis(true);
    }
    if (projectTreeRoot) {
      targetNodes = getFolderFiles(projectTreeRoot).filter(n => isSupportedSource(n.name));
      scanLabel = `all project files (${targetNodes.length} file${targetNodes.length === 1 ? '' : 's'})`;
    }
  }

  if (!targetNodes || targetNodes.length === 0) {
    showToast('No eligible source files selected to analyse.', 'warning');
    return;
  }

  // If exactly 1 file is selected:
  if (targetNodes.length === 1) {
    const singleNode = targetNodes[0];
    await openFileInTab(singleNode.path, singleNode.fileObj, singleNode.content);
    showToast(`Analyzing single file: ${singleNode.name}...`, 'info');
    sourceName.value = singleNode.path;
    return runAnalysis(false);
  }

  // Multiple files to be analysed:
  setLoading(true);
  hideResults();
  showToast(`Analyzing ${scanLabel}...`, 'info');

  try {
    const form = new FormData();
    for (const node of targetNodes) {
      let content = null;
      if (projectEdits.has(node.path)) {
        content = projectEdits.get(node.path);
      } else if (openEditorTabs.has(node.path) && activeEditorTabPath === node.path) {
        content = codeEditor.value;
      } else if (node.content !== null) {
        content = node.content;
      }

      if (content !== null) {
        form.append('files', new Blob([content], { type: 'text/plain' }), node.path);
      } else if (node.fileObj) {
        form.append('files', node.fileObj, node.path);
      } else if (projectFilesMap.has(node.path)) {
        const item = projectFilesMap.get(node.path);
        if (item.content) {
          form.append('files', new Blob([item.content], { type: 'text/plain' }), node.path);
        } else if (item.file) {
          form.append('files', item.file, node.path);
        }
      }
    }

    const res = await fetch(`${API_BASE}/analyze`, { method: 'POST', body: form });
    const contentType = res.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await res.json() : { success: false, error: await res.text() };

    if (!res.ok || data.success !== true) {
      showError(data.error || `Analysis failed (${res.status})`);
    } else {
      currentAnalysisData = data;
      renderResults(data);
      updateTreeFindings(data);
      showToast(`Analysis complete: ${data.summary?.total_vulnerabilities ?? 0} vulnerabilities found in ${targetNodes.length} files.`, 'success');
    }
  } catch (err) {
    showError(`Selective analysis failed: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

// Checkbox Toolbar Listeners
const selectAllChkEl = document.getElementById('explorer-select-all');
if (selectAllChkEl) {
  selectAllChkEl.addEventListener('change', () => {
    if (projectTreeRoot) {
      setNodeCheckedRecursive(projectTreeRoot, selectAllChkEl.checked);
      updateTreeCheckedState(projectTreeRoot);
      updateSelectionToolbar();
      renderProjectExplorer();
    }
  });
}

const scanSelectedBtnEl = document.getElementById('explorer-scan-selected');
if (scanSelectedBtnEl) {
  scanSelectedBtnEl.onclick = () => runSelectiveAnalysis('selected');
}

const scanAllProjectBtnEl = document.getElementById('explorer-scan-all');
if (scanAllProjectBtnEl) {
  scanAllProjectBtnEl.onclick = () => runSelectiveAnalysis('all');
}

const refreshTreeBtnEl = document.getElementById('explorer-refresh-btn');
if (refreshTreeBtnEl) {
  refreshTreeBtnEl.onclick = () => {
    renderProjectExplorer();
    showToast('Refreshed project structure.');
  };
}

function showFileFindingsFromProject(filePath) {
  const src = fullProjectAnalysisData || currentAnalysisData;
  if (!src || !Array.isArray(src.vulnerabilities)) return;
  const norm = p => (p || '').replace(/\\/g, '/').toLowerCase();
  const target = norm(filePath);
  const fileVulns = src.vulnerabilities.filter(v => {
    const vf = norm(v.file || '');
    return vf === target || vf.endsWith('/' + target) || target.endsWith('/' + vf);
  });

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  fileVulns.forEach(v => {
    const sev = (v.severity || 'LOW').toUpperCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const fileData = {
    ...src,
    filename: filePath,
    project: false,
    summary: {
      total_vulnerabilities: fileVulns.length,
      critical_severity: counts.CRITICAL,
      high_severity: counts.HIGH,
      medium_severity: counts.MEDIUM,
      low_severity: counts.LOW,
      filtered: 0,
      categories: {}
    },
    vulnerabilities: fileVulns
  };
  fileVulns.forEach(v => {
    const cat = v.category || 'Security';
    fileData.summary.categories[cat] = (fileData.summary.categories[cat] || 0) + 1;
  });

  currentAnalysisCode = codeEditor.value;
  renderResults(fileData);
}

// ─── Pane tabs ───────────────────────────────────────────────────────────────
function showPane(name) {
  document.querySelectorAll('.pane-tab').forEach(tab => {
    const active = tab.dataset.pane === name;
    tab.classList.toggle('pane-tab--active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  document.querySelectorAll('.pane-panel').forEach(panel => { panel.hidden = panel.dataset.panel !== name; });
}
document.querySelectorAll('.pane-tab').forEach(tab => tab.addEventListener('click', () => showPane(tab.dataset.pane)));
document.querySelectorAll('.nav-link[data-pane]').forEach(link => link.addEventListener('click', e => { e.preventDefault(); showPane(link.dataset.pane); }));

// ─── Pane splitter ───────────────────────────────────────────────────────────
(function setupPaneSplitter() {
  let dragging = false;
  const layout = document.getElementById('ide-layout');
  const applyPosition = (clientX) => {
    const rect = layout.getBoundingClientRect();
    const sidebar = document.body.classList.contains('explorer-collapsed') ? 0 : document.querySelector('.file-explorer').getBoundingClientRect().width;
    const available = rect.width - sidebar - 7;
    const left = Math.max(300, Math.min(available - 300, clientX - rect.left - sidebar));
    const right = Math.max(300, available - left);
    layout.style.setProperty('--editor-pane-width', `${left}fr`);
    layout.style.setProperty('--results-pane-width', `${right}fr`);
  };
  paneSplitter.addEventListener('pointerdown', e => { dragging = true; paneSplitter.classList.add('dragging'); paneSplitter.setPointerCapture(e.pointerId); e.preventDefault(); });
  paneSplitter.addEventListener('pointermove', e => { if (dragging && window.innerWidth > 760) applyPosition(e.clientX); });
  const stop = () => { dragging = false; paneSplitter.classList.remove('dragging'); };
  paneSplitter.addEventListener('pointerup', stop);
  paneSplitter.addEventListener('pointercancel', stop);
  paneSplitter.addEventListener('keydown', e => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const rect = paneSplitter.getBoundingClientRect();
    applyPosition(rect.left + (e.key === 'ArrowLeft' ? -24 : 24));
  });
})();

// ─── Sample / Clear ──────────────────────────────────────────────────────────
sampleBtn.addEventListener('click', async () => {
  projectFiles = null;
  projectZipFile = null;
  projectEdits = new Map();
  selectedProjectPath = null;
  currentSingleFile = null;
  currentAnalysisCode = '';
  currentAnalysisData = null;
  aiRepairResult = null;
  fullProjectAnalysisData = null;
  hideResults();

  projectFilesMap.clear();
  openEditorTabs.clear();
  activeEditorTabPath = null;

  projectFilesMap.set('security_sample.py', {
    path: 'security_sample.py',
    name: 'security_sample.py',
    file: null,
    content: SAMPLES.python
  });

  renderExplorer([{ path: 'security_sample.py', content: SAMPLES.python }], 'SAMPLE');
  explorerStatus.textContent = 'Sample loaded';
  filePreview.hidden = true;
  const closeProjBtn = document.getElementById('explorer-close-project');
  if (closeProjBtn) closeProjBtn.style.display = 'none';
  const scanAllBtn = document.getElementById('explorer-scan-all');
  if (scanAllBtn) scanAllBtn.style.display = 'none';

  await openFileInTab('security_sample.py', null, SAMPLES.python);
  updateLanguageUI();
  updateEditorState();
  codeEditor.focus();
  showToast('Loaded security sample (Python). Click Run Analysis.');
});

clearCodeBtn.addEventListener('click', () => {
  clearUploadedFile();
  codeEditor.focus();
});

// ─── Tab switching ───────────────────────────────────────────────────────────
function switchTab(tab) {
  const editorMode = tab === 'editor';
  if (codeTab) codeTab.classList.toggle('workspace-tab--active', editorMode);
  if (uploadTab) uploadTab.classList.toggle('workspace-tab--active', !editorMode);
  if (editorPanel) editorPanel.hidden = !editorMode;
  if (uploadPanel) uploadPanel.hidden = editorMode;
}
codeTab?.addEventListener('click', () => switchTab('editor'));
uploadTab?.addEventListener('click', () => switchTab('upload'));

// ─── File uploads ─────────────────────────────────────────────────────────────
browseBtn.addEventListener('click', e => { e.stopPropagation(); fileInput.click(); });
browseProjectBtn.addEventListener('click', e => { e.stopPropagation(); projectInput.click(); });
browseZipBtn.addEventListener('click', e => { e.stopPropagation(); projectZipInput.click(); });
clearBtn.addEventListener('click', e => { e.stopPropagation(); clearUploadedFile(); });

fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (!file) return;
  if (file.name.toLowerCase().endsWith('.zip')) loadProjectZip(file);
  else loadFile(file);
});
projectInput.addEventListener('change', () => { if (projectInput.files.length) loadProject(projectInput.files); });
projectZipInput.addEventListener('change', () => { if (projectZipInput.files.length) loadProjectZip(projectZipInput.files[0]); });

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  const files = Array.from(e.dataTransfer.files || []);
  if (!files.length) return;
  const zip = files.find(f => f.name && f.name.toLowerCase().endsWith('.zip'));
  if (zip && files.length === 1) loadProjectZip(zip);
  else if (files.length > 1) loadProject(files);
  else loadFile(files[0]);
});

function isSupportedSource(name) {
  const lower = name.toLowerCase();
  return ['.py', '.js', '.jsx', '.mjs', '.cjs', '.java', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh'].some(ext => lower.endsWith(ext));
}

async function loadProject(files) {
  const allList = Array.from(files);
  const list = allList.filter(f => isSupportedSource(f.name));
  if (!list.length) { showToast('No supported source files found in the selected folder.', 'error'); return; }
  const total = list.reduce((n, f) => n + f.size, 0);
  if (total > 10 * 1024 * 1024) { showToast('The project source is larger than the 10 MB limit.', 'error'); return; }
  projectFiles = list;
  projectZipFile = null;
  projectEdits = new Map();
  selectedProjectPath = null;
  currentSingleFile = null;
  currentAnalysisCode = '';
  currentAnalysisData = null;
  aiRepairResult = null;
  fullProjectAnalysisData = null;
  hideResults();

  projectFilesMap.clear();
  openEditorTabs.clear();
  activeEditorTabPath = null;

  const rootTitle = (list[0].webkitRelativePath || list[0].name).split('/')[0] || 'PROJECT';
  renderExplorer(allList.map(file => ({
    path: file.webkitRelativePath || file.name,
    file: isSupportedSource(file.name) ? file : null,
    note: isSupportedSource(file.name) ? undefined : 'This file type is not scanned.'
  })), rootTitle);

  explorerStatus.textContent = `${list.length} source files · ${allList.length} total`;
  uploadedFilename = list[0].webkitRelativePath || list[0].name;
  fileNameEl.textContent = `${list.length} source files`;
  fileSizeEl.textContent = formatSize(total);
  filePreview.hidden = false;
  analyzeBtn.disabled = false;

  const closeProjBtn = document.getElementById('explorer-close-project');
  if (closeProjBtn) closeProjBtn.style.display = 'inline-block';
  const scanAllBtn = document.getElementById('explorer-scan-all');
  if (scanAllBtn) scanAllBtn.style.display = 'inline-block';

  // Automatically open first source file in tab
  const firstScannable = list[0];
  if (firstScannable) {
    const firstRelPath = firstScannable.webkitRelativePath || firstScannable.name;
    await openFileInTab(firstRelPath, firstScannable);
  }

  updateEditorState();
  switchTab('editor');
  showToast(`Loaded ${list.length} source files.`);
}

async function loadFile(file) {
  if (!isSupportedSource(file.name)) { showToast('Unsupported file type. Use Python, JavaScript, Java, C, or C++.', 'error'); return; }
  if (file.size > 2 * 1024 * 1024) { showToast('The file is larger than the 2 MB limit.', 'error'); return; }
  try {
    const text = await file.text();
    projectFiles = null;
    projectZipFile = null;
    projectEdits = new Map();
    selectedProjectPath = null;
    currentSingleFile = file;
    currentAnalysisCode = '';
    currentAnalysisData = null;
    aiRepairResult = null;
  fullProjectAnalysisData = null;
    hideResults();

    projectFilesMap.clear();
    openEditorTabs.clear();
    activeEditorTabPath = null;

    renderExplorer([{ path: file.name, file, content: text }], file.name.toUpperCase());
    explorerStatus.textContent = '1 file loaded';
    uploadedFilename = file.name;
    sourceName.value = file.name;
    updateLanguageUI();
    fileNameEl.textContent = file.name;
    fileSizeEl.textContent = formatSize(file.size);
    filePreview.hidden = false;

    const closeProjBtn = document.getElementById('explorer-close-project');
    if (closeProjBtn) closeProjBtn.style.display = 'inline-block';

    await openFileInTab(file.name, file, text);
    updateEditorState();
    switchTab('editor');
    codeEditor.focus();
    fileInput.value = '';
    showToast(`Loaded ${file.name}. Click Run Analysis.`);
  } catch (err) {
    showToast(`Could not read the file: ${err.message}`, 'error');
  }
}

async function loadProjectZip(file) {
  if (!file.name || !file.name.toLowerCase().endsWith('.zip')) { showToast('Please choose a .zip project archive.', 'error'); return; }
  if (file.size > 50 * 1024 * 1024) { showToast('The project ZIP is larger than the 50 MB limit.', 'error'); return; }
  projectFiles = null;
  projectEdits = new Map();
  selectedProjectPath = null;
  currentSingleFile = null;
  currentAnalysisCode = '';
  currentAnalysisData = null;
  aiRepairResult = null;
  fullProjectAnalysisData = null;
  hideResults();
  explorerStatus.textContent = 'Inspecting ZIP archive…';

  try {
    const form = new FormData();
    form.append('project_zip', file, file.name);
    const res = await fetch(`${API_BASE}/inspect-zip`, { method: 'POST', body: form });
    const data = await res.json();
    if (data.success && Array.isArray(data.files) && data.files.length) {
      projectZipFile = file;
      projectFilesMap.clear();
      openEditorTabs.clear();
      activeEditorTabPath = null;

      const sources = data.file_sources || {};
      const entries = data.files.map(item => ({
        path: item.path,
        content: sources[item.path] || ''
      }));

      const rootTitle = (file.name || 'PROJECT').replace(/\.zip$/i, '');
      renderExplorer(entries, rootTitle);

      const scannableFiles = data.files.filter(f => isSupportedSource(f.path));
      explorerStatus.textContent = `${scannableFiles.length} source files · ${data.files.length} total`;
      uploadedFilename = file.name;
      fileNameEl.textContent = `Project ZIP: ${file.name}`;
      fileSizeEl.textContent = formatSize(file.size);
      filePreview.hidden = false;
      analyzeBtn.disabled = false;

      const closeProjBtn = document.getElementById('explorer-close-project');
      if (closeProjBtn) closeProjBtn.style.display = 'inline-block';
      const scanAllBtn = document.getElementById('explorer-scan-all');
      if (scanAllBtn) scanAllBtn.style.display = 'inline-block';

      const firstFile = scannableFiles[0] || data.files[0];
      if (firstFile) {
        await openFileInTab(firstFile.path, null, sources[firstFile.path] || '');
      }

      updateEditorState();
      switchTab('editor');
      showToast(`Loaded ${data.files.length} files from ${file.name}. Click Run Analysis or scan selected files.`, 'success');
      return;
    }
  } catch (err) {
    console.warn('Inspect zip fallback:', err);
  }

  // Fallback
  projectZipFile = file;
  renderExplorer([{ path: file.name, note: 'ZIP contents are listed after analysis.' }], file.name.toUpperCase());
  explorerStatus.textContent = 'ZIP ready to scan';
  uploadedFilename = file.name;
  fileNameEl.textContent = `Project ZIP: ${file.name}`;
  fileSizeEl.textContent = formatSize(file.size);
  filePreview.hidden = false;
  sourceName.value = 'project.zip';
  codeEditor.value = `Project ZIP loaded: ${file.name}\n\nClick Run Analysis to analyze the archive.`;
  analyzeBtn.disabled = false;
  const closeProjBtn = document.getElementById('explorer-close-project');
  if (closeProjBtn) closeProjBtn.style.display = 'inline-block';
  const scanAllBtn = document.getElementById('explorer-scan-all');
  if (scanAllBtn) scanAllBtn.style.display = 'inline-block';
  updateEditorState();
  switchTab('editor');
  showToast(`Loaded ZIP ${file.name}. Click Run Analysis.`);
}

function clearUploadedFile() {
  fileInput.value = '';
  projectInput.value = '';
  projectZipInput.value = '';
  filePreview.hidden = true;
  uploadedFilename = 'pasted_code.txt';
  projectFiles = null;
  projectZipFile = null;
  projectEdits = new Map();
  selectedProjectPath = null;
  currentSingleFile = null;
  currentAnalysisCode = '';
  currentAnalysisData = null;
  aiRepairResult = null;
  fullProjectAnalysisData = null;

  renderExplorer([], 'NO FOLDER OPEN');
  explorerStatus.textContent = 'Ready';
  sourceName.value = 'pasted_code.txt';
  codeEditor.value = '';
  updateEditorState();
  hideResults();

  const closeProjBtn = document.getElementById('explorer-close-project');
  if (closeProjBtn) closeProjBtn.style.display = 'none';
  const scanAllBtn = document.getElementById('explorer-scan-all');
  if (scanAllBtn) scanAllBtn.style.display = 'none';
  const selectionBar = document.getElementById('explorer-selection-bar');
  if (selectionBar) selectionBar.style.display = 'none';
}

const explorerCloseProjBtn = document.getElementById('explorer-close-project');
if (explorerCloseProjBtn) {
  explorerCloseProjBtn.addEventListener('click', () => {
    clearUploadedFile();
    showToast('Project closed.');
  });
}
const explorerScanAllBtn = document.getElementById('explorer-scan-all');
if (explorerScanAllBtn) {
  explorerScanAllBtn.addEventListener('click', () => {
    if (!projectFiles && !projectZipFile) { showToast('No project folder loaded.', 'info'); return; }
    sourceName.value = projectFiles ? 'project-folder' : 'project.zip';
    runAnalysis(true);
  });
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ─── Groq API status & model selector ────────────────────────────────────────
async function checkGroqStatus() {
  aiStatusText.textContent = 'Checking…';
  aiStatusPill.dataset.state = 'loading';
  try {
    const res = await fetch(`${API_BASE}/groq-status`);
    const data = await res.json();
    if (data.available) {
      const provider = data.provider || 'AI';
      aiStatusText.textContent = `${provider} · ${data.model || 'Ready'}`;
      aiStatusPill.dataset.state = 'ready';
      aiStatusPill.title = `Connected (${provider}) · Model: ${data.model} · Click to manage API key`;
    } else if (data.configured) {
      aiStatusText.textContent = `Key Error: ${(data.error || 'Check key').substring(0, 30)}`;
      aiStatusPill.dataset.state = 'error';
      aiStatusPill.title = `${data.error || 'API key invalid'}. Click to update key.`;
    } else {
      aiStatusText.textContent = 'Enter API Key';
      aiStatusPill.dataset.state = 'warning';
      aiStatusPill.title = 'No API key configured. Click to paste your key.';
    }
    if (data.supported_models && Array.isArray(data.supported_models)) {
      populateModelSelect(data.supported_models, data.model);
    }
    return data;
  } catch {
    aiStatusText.textContent = 'Server offline';
    aiStatusPill.dataset.state = 'error';
  }
}

async function populateModelSelect(models, currentModel) {
  modelSelect.innerHTML = '';
  models.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.label || m.id;
    if (m.id === currentModel) opt.selected = true;
    modelSelect.appendChild(opt);
  });
}

modelSelect.addEventListener('change', async () => {
  const selectedModel = modelSelect.value;
  if (!selectedModel) return;
  try {
    const res = await fetch(`${API_BASE}/groq-set-model`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: selectedModel })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Switched to ${selectedModel}`, 'success');
      aiStatusText.textContent = `AI · ${selectedModel}`;
      aiStatusPill.dataset.state = 'ready';
    } else {
      showToast(`Model switch failed: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast(`Could not switch model: ${err.message}`, 'error');
  }
});

// ─── API Key Modal ────────────────────────────────────────────────────────────
const apiKeyModal = document.getElementById('api-key-modal');
const apiKeyBtn = document.getElementById('api-key-btn');
const closeApiKeyModalBtn = document.getElementById('close-api-key-modal-btn');
const cancelApiKeyBtn = document.getElementById('cancel-api-key-btn');
const saveApiKeyBtn = document.getElementById('save-api-key-btn');
const apiKeyInput = document.getElementById('api-key-input');
const toggleKeyVisibilityBtn = document.getElementById('toggle-key-visibility-btn');
const apiKeyStatusMsg = document.getElementById('api-key-status-msg');

function openApiKeyModal() {
  if (!apiKeyModal) return;
  apiKeyModal.classList.remove('hidden');
  if (apiKeyInput) {
    apiKeyInput.focus();
  }
}

function closeApiKeyModal() {
  if (!apiKeyModal) return;
  apiKeyModal.classList.add('hidden');
  if (apiKeyStatusMsg) {
    apiKeyStatusMsg.className = 'api-key-status-msg hidden';
    apiKeyStatusMsg.textContent = '';
  }
}

if (apiKeyBtn) apiKeyBtn.addEventListener('click', openApiKeyModal);
if (aiStatusPill) aiStatusPill.addEventListener('click', openApiKeyModal);
if (closeApiKeyModalBtn) closeApiKeyModalBtn.addEventListener('click', closeApiKeyModal);
if (cancelApiKeyBtn) cancelApiKeyBtn.addEventListener('click', closeApiKeyModal);

if (apiKeyModal) {
  apiKeyModal.addEventListener('click', (e) => {
    if (e.target === apiKeyModal) closeApiKeyModal();
  });
}

if (toggleKeyVisibilityBtn && apiKeyInput) {
  toggleKeyVisibilityBtn.addEventListener('click', () => {
    if (apiKeyInput.type === 'password') {
      apiKeyInput.type = 'text';
      toggleKeyVisibilityBtn.textContent = '🔒';
    } else {
      apiKeyInput.type = 'password';
      toggleKeyVisibilityBtn.textContent = '👁️';
    }
  });
}

if (saveApiKeyBtn && apiKeyInput) {
  saveApiKeyBtn.addEventListener('click', async () => {
    const key = apiKeyInput.value.trim();
    if (!key) {
      if (apiKeyStatusMsg) {
        apiKeyStatusMsg.className = 'api-key-status-msg status-error';
        apiKeyStatusMsg.textContent = 'Please enter or paste your API key.';
      }
      return;
    }

    const spinner = saveApiKeyBtn.querySelector('.btn-spinner');
    const textSpan = saveApiKeyBtn.querySelector('.btn-text');
    if (spinner) spinner.classList.remove('hidden');
    if (textSpan) textSpan.textContent = 'Connecting…';
    saveApiKeyBtn.disabled = true;

    if (apiKeyStatusMsg) {
      apiKeyStatusMsg.className = 'api-key-status-msg status-loading';
      apiKeyStatusMsg.textContent = 'Validating key with AI API…';
    }

    try {
      const res = await fetch(`${API_BASE}/groq-set-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key, persist: true })
      });
      const data = await res.json();
      if (data.success && data.status && data.status.available) {
        if (apiKeyStatusMsg) {
          apiKeyStatusMsg.className = 'api-key-status-msg status-success';
          apiKeyStatusMsg.textContent = `Connected! Provider: ${data.status.provider}, Model: ${data.status.model}`;
        }
        showToast('API key verified and connected!', 'success');
        await checkGroqStatus();
        setTimeout(closeApiKeyModal, 1000);
      } else {
        const errMsg = data.status?.error || data.error || 'Key validation failed.';
        if (apiKeyStatusMsg) {
          apiKeyStatusMsg.className = 'api-key-status-msg status-error';
          apiKeyStatusMsg.textContent = `Connection error: ${errMsg}`;
        }
        showToast(`API error: ${errMsg}`, 'error');
        await checkGroqStatus();
      }
    } catch (err) {
      if (apiKeyStatusMsg) {
        apiKeyStatusMsg.className = 'api-key-status-msg status-error';
        apiKeyStatusMsg.textContent = `Error reaching server: ${err.message}`;
      }
    } finally {
      if (spinner) spinner.classList.add('hidden');
      if (textSpan) textSpan.textContent = 'Save & Connect';
      saveApiKeyBtn.disabled = false;
    }
  });
}

// ─── Analysis ─────────────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', runAnalysis);
analyzeRepoBtn.addEventListener('click', runRepositoryAnalysis);
document.getElementById('run-firewall-demo').addEventListener('click', runAiFirewallDemo);
document.getElementById('ai-chat-form').addEventListener('submit', sendAiChatMessage);
document.getElementById('ai-investigate-btn').addEventListener('click', runAiInvestigation);
document.getElementById('run-agentic-workflow').addEventListener('click', runAgenticWorkflow);
document.getElementById('ai-repair-btn').addEventListener('click', runAiRepair);
document.getElementById('load-repaired-code').addEventListener('click', loadRepairedCodeIntoEditor);
document.getElementById('revert-backup-code')?.addEventListener('click', revertBackupCode);
document.getElementById('download-repaired-code').addEventListener('click', downloadRepairedCode);
document.getElementById('validate-repaired-code').addEventListener('click', validateRepairedCode);
document.getElementById('export-json-btn').addEventListener('click', exportReportJSON);
document.getElementById('export-pdf-btn').addEventListener('click', exportReportPDF);
document.getElementById('clear-chat-btn').addEventListener('click', clearChat);

let backupHistory       = [];

// Context-aware chat action buttons
document.querySelectorAll('.chat-action-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById('ai-chat-input');
    const form = document.getElementById('ai-chat-form');
    if (input) {
      input.value = btn.dataset.prompt;
      input.focus();
      if (form) {
        form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      }
    }
  });
});

// Enable sending chat with Enter key (Shift+Enter for newline)
const chatInput = document.getElementById('ai-chat-input');
const chatForm = document.getElementById('ai-chat-form');
if (chatInput && chatForm) {
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const sendBtn = document.getElementById('ai-chat-send');
      if (chatInput.value.trim() && (!sendBtn || !sendBtn.disabled)) {
        chatForm.requestSubmit ? chatForm.requestSubmit() : chatForm.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      }
    }
  });
}

checkGroqStatus();

async function runAnalysis(forceProject = false) {
  const code = codeEditor.value;
  const isProjectOverview = (sourceName.value === 'project-folder' || sourceName.value === 'project.zip');
  const isProjectScan = Boolean(
    forceProject === true || ((projectFiles || projectZipFile) && isProjectOverview)
  );

  if (!isProjectScan && !code.trim()) {
    showToast('Write or paste source code first.', 'error');
    return;
  }
  setLoading(true);
  hideResults();
  try {
    let res;
    if (isProjectScan && (projectFiles || projectZipFile)) {
      const form = new FormData();
      if (projectFiles) {
        if (selectedProjectPath) projectEdits.set(selectedProjectPath, codeEditor.value);
        projectFiles.forEach(file => {
          const path = file.webkitRelativePath || file.name;
          if (projectEdits.has(path)) form.append('files', new Blob([projectEdits.get(path)], { type: 'text/plain' }), path);
          else form.append('files', file, path);
        });
      } else {
        form.append('project_zip', projectZipFile, projectZipFile.name);
      }
      res = await fetch(`${API_BASE}/analyze`, { method: 'POST', body: form });
    } else {
      const activeFilename = sourceName.value.trim() || uploadedFilename || 'source.py';
      res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, filename: activeFilename })
      });
    }
    const contentType = res.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await res.json() : { success: false, error: await res.text() };
    if (!res.ok || data.success !== true) {
      showError(data.error || `Analysis failed with HTTP ${res.status}`);
    } else {
      currentAnalysisCode = code;
      currentAnalysisData = data;
      renderResults(data);
    }
  } catch (err) {
    showError(`Could not reach the analysis server.\n\nMake sure app.py is running.\n\nError: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function runRepositoryAnalysis() {
  const url = repoUrlInput.value.trim();
  if (!url) { showToast('Enter a GitHub repository URL first.', 'error'); return; }
  analyzeRepoBtn.disabled = true;
  const oldText = analyzeRepoBtn.textContent;
  analyzeRepoBtn.textContent = 'Analyzing…';
  hideResults();
  try {
    const res = await fetch(`${API_BASE}/analyze-repository`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, branch: repoBranchInput.value.trim() || null })
    });
    const data = await res.json();
    if (!res.ok || data.success !== true) showError(data.error || `Repository analysis failed (${res.status})`);
    else renderResults(data);
  } catch (err) {
    showError(`Could not connect to SecureCode server.\n\n${err.message}`);
  } finally { analyzeRepoBtn.disabled = false; analyzeRepoBtn.textContent = oldText; }
}

function setLoading(on) {
  analyzeBtn.disabled = on;
  btnText.hidden = on;
  btnSpinner.hidden = !on;
}

// ─── Results ──────────────────────────────────────────────────────────────────
function hideResults() {
  resultsSection.hidden = true;
  errorCard.hidden = true;
  summaryBar.hidden = true;
  vulnSection.hidden = true;
  symbolSection.hidden = true;
  statsSection.hidden = true;
  projectGraphSection.hidden = true;
  if (reportToolbar) reportToolbar.hidden = true;

  // Clear previous vulnerability cards and symbol table
  if (vulnList) vulnList.innerHTML = '';
  if (symbolBody) symbolBody.innerHTML = '';

  // Clear and hide AI review and repair sections so old code findings never stack
  const reviewSec = document.getElementById('ai-review-section');
  if (reviewSec) reviewSec.hidden = true;
  const reviewFindings = document.getElementById('ai-review-findings');
  if (reviewFindings) reviewFindings.innerHTML = '';
  const reviewSummary = document.getElementById('ai-review-summary');
  if (reviewSummary) reviewSummary.textContent = '';
  const reviewNote = document.getElementById('ai-review-note');
  if (reviewNote) reviewNote.textContent = '';

  const repairSec = document.getElementById('ai-repair-section');
  if (repairSec) repairSec.hidden = true;
  const repairChanges = document.getElementById('ai-repair-changes');
  if (repairChanges) repairChanges.innerHTML = '';
  const repairedCode = document.getElementById('ai-repaired-code');
  if (repairedCode) repairedCode.textContent = '';
  const repairSummary = document.getElementById('ai-repair-summary');
  if (repairSummary) repairSummary.textContent = '';
  const syntaxBadge = document.getElementById('ai-repair-syntax-badge');
  if (syntaxBadge) syntaxBadge.hidden = true;
}

function showError(msg) {
  showPane('results');
  resultsSection.hidden = false;
  errorCard.hidden = false;
  errorMsg.textContent = msg;
}

function calculateSecurityScore(data) {
  const vulns = data.vulnerabilities || [];
  if (!vulns.length) return 100;
  const weights = { CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1 };
  const totalPenalty = vulns.reduce((sum, v) => sum + (weights[v.severity] || 1), 0);
  return Math.max(0, Math.round(100 - Math.min(100, totalPenalty)));
}

function renderResults(data) {
  if (data.project) fullProjectAnalysisData = data;
  currentAnalysisData = data;
  currentAnalysisCode = codeEditor.value;
  aiRepairResult = null;
  fullProjectAnalysisData = null;

  showPane('results');
  resultsSection.hidden = false;

  // Clean wipe of vulnerability list
  vulnList.innerHTML = '';

  if (fullProjectAnalysisData && !data.project) {
    const filterBanner = document.createElement('div');
    filterBanner.className = 'file-filter-banner';
    const totalProjVulns = fullProjectAnalysisData.vulnerabilities?.length || 0;
    const fileCount = data.vulnerabilities?.length || 0;
    filterBanner.innerHTML = `
      <span>📄 Viewing findings for: <strong>${escHtml(data.filename)}</strong> (${fileCount} issue${fileCount === 1 ? '' : 's'})</span>
      <button type="button" class="btn btn-ghost btn-xs" id="clear-file-filter-btn" style="cursor:pointer; padding:2px 8px;">Show All Project Findings (${totalProjVulns})</button>
    `;
    vulnList.appendChild(filterBanner);
    const clearBtn = filterBanner.querySelector('#clear-file-filter-btn');
    if (clearBtn) {
      clearBtn.onclick = () => renderResults(fullProjectAnalysisData);
    }
  }

  if (data.files && data.files.length && !projectFiles && !projectZipFile && projectFilesMap.size === 0) {
    const files = data.files.map(item => ({ path: item.file, note: 'File analyzed from project. Upload folder to edit individual files.' }));
    renderExplorer(files, data.repository ? `${data.repository.owner}/${data.repository.name}` : (data.filename || 'PROJECT').toUpperCase());
    explorerStatus.textContent = `${files.length} analyzed files`;
  } else if (data.filename && !projectFiles && !projectZipFile && projectFilesMap.size === 0) {
    renderExplorer([{ path: data.filename, file: currentSingleFile }], data.filename.toUpperCase());
    explorerStatus.textContent = 'Analysis complete';
  }
  errorCard.hidden = true;
  summaryBar.hidden = false;
  if (reportToolbar) reportToolbar.hidden = false;

  document.getElementById('sc-total-val').textContent   = data.summary?.total_vulnerabilities ?? 0;
  document.getElementById('sc-critical-val').textContent = data.summary?.critical_severity ?? 0;
  document.getElementById('sc-high-val').textContent    = data.summary?.high_severity ?? 0;
  document.getElementById('sc-medium-val').textContent  = data.summary?.medium_severity ?? 0;
  document.getElementById('sc-low-val').textContent     = data.summary?.low_severity ?? 0;
  const score = calculateSecurityScore(data);
  document.getElementById('sc-score-val').textContent   = score;
  document.getElementById('sc-score-val').style.color =
    score >= 80 ? 'var(--sev-low)' : score >= 60 ? 'var(--sev-medium)' : 'var(--sev-high)';

  if (data.language_detection && !data.project) {
    const d = data.language_detection;
    showToast(`Detected ${d.language} (${Math.round((d.confidence || 0) * 100)}% confidence)`, 'info');
  }

  // Always show vulnerability section and render findings or clean badge
  vulnSection.hidden = false;
  if (data.vulnerabilities && data.vulnerabilities.length) {
    renderVulnList(data.vulnerabilities);
  } else {
    vulnList.innerHTML = `
      <div class="vuln-clean-card">
        <div class="clean-icon">🛡️</div>
        <div class="clean-body">
          <h4>No Security Vulnerabilities Detected</h4>
          <p>Zero high-confidence vulnerabilities were found in <strong>${escHtml(data.filename || 'this file')}</strong>.</p>
        </div>
      </div>
    `;
    currentFilter = 'all';
    document.querySelectorAll('.pill').forEach(p => p.classList.toggle('pill--active', p.dataset.filter === 'all'));
  }

  const symbols = data.symbol_table || {};
  symbolSection.hidden = Object.keys(symbols).length === 0;
  renderSymbolTable(symbols);
  if (data.stats && Object.keys(data.stats).length) { statsSection.hidden = false; renderStats(data.stats); }
  if (data.project_graph) renderProjectGraph(data.project_graph, data.repository);
  if (data.sca_report) { renderScaResults(data.sca_report); showPane('dependencies'); }
  updateTreeFindings(data);
}

// ─── Report Export ────────────────────────────────────────────────────────────
async function exportReportJSON() {
  if (!currentAnalysisData) { showToast('Run analysis first to generate a report.', 'error'); return; }
  try {
    const res = await fetch(`${API_BASE}/export-report`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis: currentAnalysisData, format: 'json' })
    });
    if (!res.ok) { showToast('Report export failed.', 'error'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'securecode-report.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('JSON report downloaded!', 'success');
  } catch (err) { showToast(`Export failed: ${err.message}`, 'error'); }
}

function exportReportPDF() {
  if (!currentAnalysisData) { showToast('Run analysis first to generate a report.', 'error'); return; }
  try {
    const summary = currentAnalysisData.summary || {};
    const vulns = currentAnalysisData.vulnerabilities || [];
    const filename = currentAnalysisData.filename || 'analysis';
    const score = calculateSecurityScore(currentAnalysisData);

    // Build a printable page
    const html = `<!DOCTYPE html>
<html><head><title>SecureCode AI Report</title>
<style>
  body { font-family: Arial, sans-serif; padding: 32px; color: #111; max-width: 900px; margin: 0 auto; }
  h1 { color: #1d4ed8; } h2 { color: #374151; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
  .meta { color: #64748b; font-size: .9rem; margin-bottom: 24px; }
  .score { font-size: 2rem; font-weight: 800; color: ${score >= 80 ? '#059669' : score >= 60 ? '#d97706' : '#e11d48'}; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
  .sc { border: 1px solid #ddd; border-radius: 8px; padding: 12px; text-align: center; }
  .sc .val { font-size: 1.8rem; font-weight: 800; } .sc .lbl { font-size: .75rem; color: #64748b; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: 12px 0; }
  th { background: #f1f5f9; padding: 8px 10px; text-align: left; border-bottom: 2px solid #ddd; }
  td { padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; word-break: break-word; }
  .crit { color: #dc2626; font-weight: 700; } .high { color: #e11d48; font-weight: 700; }
  .med { color: #d97706; font-weight: 700; } .low { color: #059669; font-weight: 700; }
</style></head><body>
<h1>🛡️ SecureCode AI Security Report</h1>
<p class="meta">File: ${escHtml(filename)} &nbsp;|&nbsp; Generated: ${new Date().toLocaleString()}</p>
<h2>Security Score</h2>
<div class="score">${score}/100</div>
<h2>Summary</h2>
<div class="summary-grid">
  <div class="sc"><div class="val">${summary.total_vulnerabilities || 0}</div><div class="lbl">Total</div></div>
  <div class="sc"><div class="val crit">${summary.critical_severity || 0}</div><div class="lbl">Critical</div></div>
  <div class="sc"><div class="val high">${summary.high_severity || 0}</div><div class="lbl">High</div></div>
  <div class="sc"><div class="val med">${summary.medium_severity || 0}</div><div class="lbl">Medium</div></div>
</div>
<h2>Vulnerabilities (${vulns.length})</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>File</th><th>Line</th><th>Description</th><th>Fix</th></tr>
${vulns.map(v => `<tr>
  <td class="${(v.severity || '').toLowerCase()}">${escHtml(v.severity || '')}</td>
  <td>${escHtml(v.category || '')}</td>
  <td style="font-family:monospace;font-size:.78rem">${escHtml(v.file || '')}</td>
  <td>${escHtml(String(v.line || ''))}</td>
  <td>${escHtml(v.description || v.title || '')}</td>
  <td>${escHtml(v.suggested_fix || v.recommendation || '')}</td>
</tr>`).join('')}
</table>
</body></html>`;
    const win = window.open('', '_blank');
    win.document.write(html);
    win.document.close();
    win.print();
  } catch (err) { showToast(`PDF export failed: ${err.message}`, 'error'); }
}

// ─── AI Firewall Demo ─────────────────────────────────────────────────────────
async function runAiFirewallDemo() {
  const button = document.getElementById('run-firewall-demo');
  const summary = document.getElementById('firewall-demo-summary');
  const resultsEl = document.getElementById('firewall-demo-results');
  button.disabled = true; button.textContent = 'Running simulations…';
  summary.textContent = 'Checking harmless attack samples against the local deterministic firewall…';
  resultsEl.replaceChildren();
  try {
    const response = await fetch(`${API_BASE}/ai-firewall/demo`);
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.error || `Firewall test failed (${response.status})`);
    summary.textContent = `${data.passed}/${data.total} simulated cases behaved as expected.`;
    data.results.forEach(item => {
      const card = document.createElement('article'); card.className = 'firewall-case';
      const head = document.createElement('div'); head.className = 'firewall-case-head';
      const title = document.createElement('h3'); title.textContent = item.name;
      const verdict = document.createElement('span'); verdict.className = `firewall-verdict ${item.passed ? 'pass' : 'fail'}`;
      verdict.textContent = `${item.passed ? 'PASS' : 'CHECK'} · ${item.actual}`;
      head.append(title, verdict);
      const category = document.createElement('p'); category.textContent = item.category;
      const payload = document.createElement('code'); payload.className = 'firewall-payload'; payload.textContent = item.payload;
      const reason = document.createElement('p'); reason.textContent = item.reason;
      card.append(head, category, payload, reason);
      resultsEl.appendChild(card);
    });
  } catch (error) { summary.textContent = `Could not run firewall simulations: ${error.message}`; }
  finally { button.disabled = false; button.textContent = 'Run simulated attacks'; }
}

// ─── AI Chat (with streaming support & markdown formatting) ──────────────────
function renderMarkdownText(text) {
  if (!text) return '';
  let out = escHtml(text);

  // Fenced code blocks ```lang\n...```
  out = out.replace(/```(?:[a-zA-Z0-9_-]+)?\n?([\s\S]*?)```/g, (_, code) => {
    return `<pre class="chat-code-block"><code>${code.trim()}</code></pre>`;
  });

  // Inline code `...`
  out = out.replace(/`([^`]+)`/g, '<code class="chat-inline-code">$1</code>');

  // Headings
  out = out.replace(/^#{1,4}\s+(.+)$/gm, '<h4 class="chat-heading">$1</h4>');

  // Bold & Italic
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  // Bullet lists
  out = out.replace(/(?:^[*-]\s+(.+)$\n?)+/gm, (match) => {
    const items = match.trim().split('\n').map(line => {
      const itemText = line.replace(/^[*-]\s+/, '').trim();
      return `<li>${itemText}</li>`;
    }).join('');
    return `<ul class="chat-bullet-list">${items}</ul>`;
  });

  // Clean paragraphs
  const parts = out.split(/\n{2,}/);
  out = parts.map(p => {
    p = p.trim();
    if (!p) return '';
    if (p.startsWith('<pre') || p.startsWith('<h4') || p.startsWith('<ul')) return p;
    return `<p class="chat-paragraph">${p.replace(/\n/g, '<br/>')}</p>`;
  }).join('');

  return out;
}

function clearChat() {
  const messages = document.getElementById('ai-chat-messages');
  messages.innerHTML = '<div class="ai-chat-bubble ai-chat-assistant">Chat cleared. Ask me anything about your code or vulnerabilities.</div>';
}

async function sendAiChatMessage(event) {
  event.preventDefault();
  const input = document.getElementById('ai-chat-input');
  const send = document.getElementById('ai-chat-send');
  const messages = document.getElementById('ai-chat-messages');
  const message = input.value.trim();
  if (!message) return;

  const addBubble = (content, role, isHtml = false) => {
    const bubble = document.createElement('div');
    bubble.className = `ai-chat-bubble ai-chat-${role}`;
    if (isHtml) bubble.innerHTML = content;
    else bubble.textContent = content;
    messages.appendChild(bubble);
    bubble.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    return bubble;
  };

  addBubble(message, 'user');
  input.value = ''; input.disabled = true; send.disabled = true;
  const pending = addBubble('<span class="status-dot-sm"></span> Thinking…', 'assistant', true);

  // Exact current analysis data - do not send old code/findings
  const currentCode = currentAnalysisCode || codeEditor.value || '';
  const currentFilename = (currentAnalysisData && currentAnalysisData.filename) || sourceName.value || 'source.py';
  const currentFindings = (currentAnalysisData && Array.isArray(currentAnalysisData.vulnerabilities)) ? currentAnalysisData.vulnerabilities : [];

  try {
    const streamRes = await fetch(`${API_BASE}/ai-chat/stream`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        code: currentCode,
        filename: currentFilename,
        findings: currentFindings
      })
    });
    if (streamRes.ok && streamRes.headers.get('content-type')?.includes('text/event-stream')) {
      pending.innerHTML = '';
      const reader = streamRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const parsed = JSON.parse(line.slice(6));
            if (parsed.chunk) {
              fullText += parsed.chunk;
              pending.innerHTML = renderMarkdownText(fullText);
            }
            if (parsed.error) {
              pending.innerHTML = `<span style="color:var(--sev-high)">Error: ${escHtml(parsed.error)}</span>`;
            }
          } catch {}
        }
      }
      if (!fullText) pending.textContent = 'No response received. Please try again.';
      else pending.innerHTML = renderMarkdownText(fullText);
    } else {
      // Non-streaming fallback
      const res = await fetch(`${API_BASE}/ai-chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message,
          code: currentCode,
          filename: currentFilename,
          findings: currentFindings
        })
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || `Chat failed (${res.status})`);
      pending.innerHTML = renderMarkdownText(data.answer);
      if (Array.isArray(data.suggestions) && data.suggestions.length) {
        const suggestions = document.createElement('p'); suggestions.className = 'ai-chat-suggestions';
        suggestions.textContent = 'Suggestions: ' + data.suggestions.join(' · ');
        messages.appendChild(suggestions);
      }
    }
  } catch (err) {
    pending.innerHTML = `<span style="color:var(--sev-high)">Chat failed: ${escHtml(err.message)}</span>`;
  } finally {
    input.disabled = false; send.disabled = false; input.focus();
    pending.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ─── AI Investigation ─────────────────────────────────────────────────────────
async function runAiInvestigation() {
  const button = document.getElementById('ai-investigate-btn');
  const section = document.getElementById('ai-review-section');
  const summary = document.getElementById('ai-review-summary');
  const list = document.getElementById('ai-review-findings');
  const note = document.getElementById('ai-review-note');
  if (!currentAnalysisCode.trim() || !currentAnalysisData) {
    showToast('Run a single-file scan first. Project-wide AI investigation requires running analysis on the project.', 'error'); return;
  }
  const oldLabel = button.textContent;
  button.disabled = true; button.textContent = 'Investigating with Groq AI…';
  section.hidden = false;
  summary.textContent = 'Groq AI is performing a two-pass security review. This may take 15–60 seconds…';
  list.innerHTML = ''; note.textContent = '';
  try {
    const res = await fetch(`${API_BASE}/ai-investigate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: currentAnalysisCode,
        filename: currentAnalysisData.filename || sourceName.value || 'source.py',
        findings: currentAnalysisData.vulnerabilities || [],
        graph_context: currentAnalysisData.project_graph || {}
      })
    });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || `AI review failed (${res.status})`);
    summary.textContent = `${data.summary || 'AI review completed.'} · ${data.findings.length} finding(s) · ${data.model} · ${data.passes} passes`;
    if (!data.findings.length) {
      list.innerHTML = '<p>No additional AI findings survived the verification pass. This does not prove the code is secure.</p>';
    }
    (data.findings || []).forEach(f => {
      const card = document.createElement('article'); card.className = 'ai-finding';
      const title = document.createElement('h3'); title.textContent = `${f.severity} · ${f.title} (line ${f.line})`;
      const detail = document.createElement('p'); detail.textContent = `${f.category} · confidence ${(f.confidence * 100).toFixed(0)}%`;
      const evidence = document.createElement('pre'); evidence.textContent = f.evidence || 'No code excerpt supplied.';
      const reasoning = document.createElement('p'); reasoning.textContent = f.reasoning || '';
      const recommendation = document.createElement('p'); recommendation.textContent = `Recommendation: ${f.recommendation || 'Review manually.'}`;
      card.append(title, detail, evidence, reasoning, recommendation);
      list.appendChild(card);
    });
    note.textContent = data.note || 'AI findings are advisory; verify manually. No source code was changed.';
    return true;
  } catch (err) {
    summary.textContent = `AI investigation failed: ${err.message}`;
    note.textContent = 'Check that GROQ_API_KEY is set and the server is running.';
    return false;
  } finally { button.disabled = false; button.textContent = oldLabel; }
}

// ─── AI Repair ───────────────────────────────────────────────────────────────
async function runAiRepair() {
  const button = document.getElementById('ai-repair-btn');
  const section = document.getElementById('ai-repair-section');
  const summary = document.getElementById('ai-repair-summary');
  const changesEl = document.getElementById('ai-repair-changes');
  const note = document.getElementById('ai-repair-note');
  const validation = document.getElementById('ai-repair-validation');
  const roundsProgression = document.getElementById('ai-repair-rounds-progression');
  const roundsBadge = document.getElementById('ai-repair-rounds-badge');

  if (!currentAnalysisCode.trim() || !currentAnalysisData) {
    showToast('Run a single-file scan first. AI repair works on the analyzed code.', 'error'); return false;
  }
  const originalLabel = button.textContent;
  button.disabled = true; button.textContent = 'Auto-repairing with AI (Max 3 rounds)…';
  section.hidden = false;
  summary.textContent = 'Running autonomous self-healing loop: AI repairs code, static analyzer re-checks, repeats until clean (max 3 rounds)…';
  changesEl.replaceChildren();
  if (roundsProgression) roundsProgression.replaceChildren();
  if (roundsBadge) roundsBadge.hidden = true;
  note.textContent = ''; validation.textContent = '';
  document.getElementById('load-repaired-code').disabled = true;
  document.getElementById('download-repaired-code').disabled = true;
  document.getElementById('validate-repaired-code').disabled = true;

  try {
    const res = await fetch(`${API_BASE}/ai-auto-repair-loop`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: currentAnalysisCode,
        filename: currentAnalysisData.filename || sourceName.value || 'source.py',
        findings: currentAnalysisData.vulnerabilities || [],
        max_iterations: 3
      })
    });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || `AI repair failed (${res.status})`);
    aiRepairResult = data;
    document.getElementById('ai-repaired-code').textContent = data.repaired_code || '';
    renderSplitDiff(currentAnalysisCode, data.repaired_code || '');
    document.querySelector('.ai-repaired-code-wrap').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Render Round Progression
    if (roundsProgression && Array.isArray(data.rounds)) {
      roundsProgression.replaceChildren();
      data.rounds.forEach(r => {
        const pill = document.createElement('div');
        pill.className = `round-pill round-pill--${r.status.toLowerCase()}`;
        pill.innerHTML = `<span>Round ${r.round}:</span> <b>${r.findings_before}</b> → <b>${r.findings_after}</b> vulns ${r.status === 'CLEAN' ? '✓ Clean' : (r.status === 'IMPROVED' ? '↓ Reduced' : '')}`;
        roundsProgression.appendChild(pill);
      });
    }

    if (roundsBadge) {
      roundsBadge.hidden = false;
      roundsBadge.textContent = data.clean ? `✓ Clean (${data.total_rounds} Round${data.total_rounds === 1 ? '' : 's'})` : `${data.total_rounds}/3 Rounds (Reduced to ${data.final_vulns_count})`;
      roundsBadge.className = `syntax-badge syntax-badge--${data.clean ? 'ok' : 'warn'}`;
    }

    summary.textContent = `${data.summary || 'Repair complete.'} · ${data.change_count || 0} change group(s) · ${data.provider} (${data.model})`;

    if (!(data.changes || []).length) {
      changesEl.innerHTML = '<p>The AI returned code with no line-level differences. No repair was needed or generated.</p>';
    }
    (data.changes || []).forEach(change => {
      const card = document.createElement('article'); card.className = 'ai-finding';
      const title = document.createElement('h3');
      const oldRange = change.original_lines && change.original_lines.start ? `original lines ${change.original_lines.start}${change.original_lines.end !== change.original_lines.start ? `–${change.original_lines.end}` : ''}` : 'no original lines (addition)';
      const newRange = change.repaired_lines && change.repaired_lines.start ? `repaired lines ${change.repaired_lines.start}${change.repaired_lines.end !== change.repaired_lines.start ? `–${change.repaired_lines.end}` : ''}` : 'no repaired lines (removal)';
      title.textContent = `Change ${change.id}: ${change.change_type} · ${oldRange} → ${newRange}`;
      const beforeLabel = document.createElement('h4'); beforeLabel.textContent = 'Before';
      const before = document.createElement('pre'); before.textContent = change.before || '(no lines)';
      const afterLabel = document.createElement('h4'); afterLabel.textContent = 'After';
      const after = document.createElement('pre'); after.textContent = change.after || '(no lines)';
      const reason = document.createElement('p'); reason.textContent = `Why: ${change.reason || 'Security fix applied in auto-repair loop.'}`;
      const benefit = document.createElement('p'); benefit.textContent = `Security benefit: ${change.security_benefit || 'Eliminates attack vector.'}`;
      const category = document.createElement('p'); category.textContent = `Vulnerability addressed: ${change.vulnerability_addressed || 'Security Issue'}`;
      card.append(title, beforeLabel, before, afterLabel, after, reason, benefit, category);
      changesEl.appendChild(card);
    });

    document.getElementById('load-repaired-code').disabled = false;
    document.getElementById('download-repaired-code').disabled = false;
    document.getElementById('validate-repaired-code').disabled = false;

    // Syntax verification badge
    const syntaxBadge = document.getElementById('ai-repair-syntax-badge');
    if (syntaxBadge && data.syntax_verification) {
      syntaxBadge.hidden = false;
      const passed = data.syntax_verification.passed;
      syntaxBadge.className = `syntax-badge syntax-badge--${passed ? 'ok' : 'err'}`;
      syntaxBadge.textContent = passed ? '✓ Syntax Verified' : '⚠ Syntax Warning';
      syntaxBadge.title = data.syntax_verification.details || '';
    }

    if (data.validation_data) {
      validation.textContent = `Re-validation: ${data.final_vulns_count} finding(s) reported in final repaired code. Score: ${calculateSecurityScore(data.validation_data)}/100.`;
    }

    const limitations = Array.isArray(data.limitations) ? data.limitations.join(' ') : '';
    note.textContent = `${data.note || ''}${limitations ? ' Model limitations: ' + limitations : ''}`;
    return true;
  } catch (err) {
    summary.textContent = `AI repair failed: ${err.message}`;
    note.textContent = 'Check your API key in the header and that the server is running.';
    return false;
  } finally { button.disabled = false; button.textContent = originalLabel; }
}

// ─── Agentic workflow ─────────────────────────────────────────────────────────
async function runAgenticWorkflow() {
  const button = document.getElementById('run-agentic-workflow');
  const status = document.getElementById('agentic-workflow-status');
  if (!currentAnalysisCode.trim() || !currentAnalysisData) {
    showToast('Run the static analyzer first, then start the agentic workflow.', 'error'); return;
  }
  const setStep = (name, state, message) => {
    const item = document.querySelector(`#agentic-steps [data-step="${name}"]`);
    if (item) { item.classList.remove('step-active', 'step-done', 'step-error'); item.classList.add(`step-${state}`); }
    status.textContent = message;
  };
  button.disabled = true; button.textContent = 'Workflow running…';
  document.querySelectorAll('#agentic-steps li').forEach(item => { item.classList.remove('step-active', 'step-error'); if (item.dataset.step !== 'scan') item.classList.remove('step-done'); });
  try {
    setStep('investigate', 'active', 'Step 2/4: AI is investigating findings…');
    const investigated = await runAiInvestigation();
    if (!investigated) { setStep('investigate', 'error', 'Workflow stopped: investigation failed.'); return; }
    setStep('investigate', 'done', 'Investigation completed.');
    setStep('repair', 'active', 'Step 3/4: Running autonomous auto-repair loop (max 3 rounds)…');
    const repaired = await runAiRepair();
    if (!repaired) { setStep('repair', 'error', 'Workflow stopped: repair generation failed.'); return; }
    setStep('repair', 'done', 'Auto-repair loop completed.');
    setStep('validate', 'active', 'Step 4/4: Re-running static analyzer validation…');
    const validated = await validateRepairedCode();
    if (!validated) { setStep('validate', 'error', 'Repair generated, but validation failed.'); return; }
    setStep('validate', 'done', 'Workflow complete! Review changes and click "Accept & Apply Repair" to load into editor.');
  } finally { button.disabled = false; button.textContent = 'Run Agentic Workflow'; }
}

function loadRepairedCodeIntoEditor() {
  if (!aiRepairResult || typeof aiRepairResult.repaired_code !== 'string') return;
  const confirmed = window.confirm('Accept & Apply the AI-repaired code into the editor? A restore point will be saved so you can revert at any time.');
  if (!confirmed) return;
  backupHistory.push({
    code: codeEditor.value,
    filename: sourceName.value,
    timestamp: new Date().toLocaleTimeString()
  });
  const revertBtn = document.getElementById('revert-backup-code');
  if (revertBtn) revertBtn.disabled = false;
  const backupStatus = document.getElementById('ai-backup-status');
  if (backupStatus) {
    backupStatus.textContent = `Restore point saved at ${new Date().toLocaleTimeString()}. Click "Revert to Backup" to undo.`;
  }
  codeEditor.value = aiRepairResult.repaired_code;
  if (aiRepairResult.filename) sourceName.value = aiRepairResult.filename;
  if (activeEditorTabPath && openEditorTabs.has(activeEditorTabPath)) {
    const tab = openEditorTabs.get(activeEditorTabPath);
    tab.content = aiRepairResult.repaired_code;
    tab.isDirty = true;
    projectEdits.set(activeEditorTabPath, aiRepairResult.repaired_code);
    renderEditorTabs();
  } else if (selectedProjectPath) {
    projectEdits.set(selectedProjectPath, aiRepairResult.repaired_code);
  }
  updateEditorState(); codeEditor.focus(); codeEditor.scrollTop = 0;
  codeEditor.scrollIntoView({ behavior: 'smooth', block: 'center' });
  showToast('Repaired code applied! Tab marked modified (●). Run Re-analyze to verify.', 'success');
}

function revertBackupCode() {
  if (!backupHistory.length) { showToast('No restore points available.', 'error'); return; }
  const backup = backupHistory.pop();
  codeEditor.value = backup.code;
  if (backup.filename) sourceName.value = backup.filename;
  if (activeEditorTabPath && openEditorTabs.has(activeEditorTabPath)) {
    const tab = openEditorTabs.get(activeEditorTabPath);
    tab.content = backup.code;
    projectEdits.set(activeEditorTabPath, backup.code);
    renderEditorTabs();
  }
  updateEditorState(); codeEditor.focus();
  const revertBtn = document.getElementById('revert-backup-code');
  const backupStatus = document.getElementById('ai-backup-status');
  if (revertBtn) revertBtn.disabled = backupHistory.length === 0;
  if (backupStatus) {
    backupStatus.textContent = backupHistory.length ? `${backupHistory.length} earlier restore point(s) available.` : '';
  }
  showToast(`Reverted back to restore point (${backup.timestamp}).`, 'info');
}

function downloadRepairedCode() {
  if (!aiRepairResult || typeof aiRepairResult.repaired_code !== 'string') return;
  const code = aiRepairResult.repaired_code;
  let filename = (aiRepairResult.filename || sourceName.value || uploadedFilename || 'repaired_source').split(/[\\\/]/).pop();
  filename = filename.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
  const hasKnownExtension = /\.(py|js|jsx|mjs|cjs|java|c|h|cc|cpp|cxx|hpp|hh)$/i.test(filename);
  if (!hasKnownExtension) {
    const detected = syntaxDetectLanguage(code, filename).language;
    const extensions = { Python: '.py', JavaScript: '.js', Java: '.java', C: '.c', 'C++': '.cpp' };
    const extension = extensions[detected];
    filename = filename.replace(/\.[^.]*$/, '');
    filename = (filename || 'repaired_source') + (extension || '.txt');
  }
  const extension = (filename.match(/\.([^.]+)$/) || [, 'txt'])[1].toLowerCase();
  const mimeTypes = { py: 'text/x-python', js: 'text/javascript', jsx: 'text/javascript', mjs: 'text/javascript', java: 'text/x-java-source', c: 'text/x-c', h: 'text/x-c', cc: 'text/x-c++src', cpp: 'text/x-c++src', cxx: 'text/x-c++src', hpp: 'text/x-c++hdr', txt: 'text/plain' };
  const blob = new Blob([code], { type: `${mimeTypes[extension] || 'text/plain'};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename || 'repaired_source.txt';
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function validateRepairedCode() {
  if (!aiRepairResult || typeof aiRepairResult.repaired_code !== 'string') return;
  const button = document.getElementById('validate-repaired-code');
  const output = document.getElementById('ai-repair-validation');
  const original = button.textContent;
  button.disabled = true; button.textContent = 'Re-analyzing…';
  output.textContent = 'Running the static analyzer on the proposed repaired code…';
  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: aiRepairResult.repaired_code, filename: aiRepairResult.filename || 'repaired_source.py' })
    });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || `Re-analysis failed (${res.status})`);
    const count = data.summary && data.summary.total_vulnerabilities != null ? data.summary.total_vulnerabilities : (data.vulnerabilities || []).length;
    const score = calculateSecurityScore(data);
    output.textContent = `Re-analysis: ${count} finding(s) reported. Security score: ${score}/100. Review manually — this is a static-analysis result, not a security guarantee.`;
    currentAnalysisCode = aiRepairResult.repaired_code;
    currentAnalysisData = data;
    renderResults(data);
    return true;
  } catch (err) {
    output.textContent = `Validation failed: ${err.message}`;
    return false;
  } finally { button.disabled = false; button.textContent = original; }
}

// ─── Project graph ────────────────────────────────────────────────────────────
function renderProjectGraph(graph, repository) {
  projectGraphSection.hidden = false;
  const summary = graph.graph_summary || {};
  projectGraphSummary.innerHTML = '';
  [
    ['Files indexed', summary.files_indexed ?? 0],
    ['Import edges', summary.import_edges ?? 0],
    ['Cross-file calls', summary.cross_file_call_edges ?? 0],
    ['Flow candidates', summary.dataflow_candidates ?? 0],
    ['Unused functions', summary.unused_functions_count ?? 0],
    ['Broken imports', summary.broken_imports_count ?? 0]
  ].forEach(([label, value]) => {
    const item = document.createElement('div'); item.className = 'stat-item';
    item.innerHTML = `<div class="stat-key">${escHtml(label)}</div><div class="stat-val">${escHtml(value)}</div>`;
    projectGraphSummary.appendChild(item);
  });
  document.getElementById('project-imports').textContent = (graph.imports || []).length;
  document.getElementById('project-calls').textContent = (graph.call_edges || []).length;
  document.getElementById('project-flows-count').textContent = (graph.dataflow_candidates || []).length;
  const blocks = [];
  if (repository) blocks.push(`<p><b>Repository:</b> ${escHtml(repository.owner)}/${escHtml(repository.name)} · branch ${escHtml(repository.branch)} · ${escHtml(repository.files_selected)} files fetched</p>`);

  // Architectural classification breakdown
  if (graph.architecture_summary) {
    const tiers = Object.entries(graph.architecture_summary).map(([tier, count]) =>
      `<span class="arch-badge arch-badge--${tier}">${escHtml(tier)}: ${count}</span>`
    ).join(' ');
    blocks.push(`<h3>Project Architecture Breakdown</h3><div style="display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 12px">${tiers}</div>`);
  }

  // Broken imports warning
  if (graph.broken_imports && graph.broken_imports.length) {
    blocks.push('<h3 style="color:var(--sev-high)">⚠ Broken or Unresolved Local Imports</h3><ul>' +
      graph.broken_imports.map(b => `<li><code>${escHtml(b.file)}</code>: import <b>${escHtml(b.import)}</b> — ${escHtml(b.reason)}</li>`).join('') +
      '</ul>');
  }

  // Unused functions
  if (graph.unused_functions && graph.unused_functions.length) {
    blocks.push('<h3>Unused / Dead Function Candidates</h3><ul>' +
      graph.unused_functions.slice(0, 20).map(u => `<li><code>${escHtml(u.name)}()</code> in <code>${escHtml(u.file)}</code> (never called in project)</li>`).join('') +
      '</ul>');
  }

  // Import relationships
  if ((graph.imports || []).length) blocks.push('<h3>Import relationships</h3><ul>' + graph.imports.slice(0, 80).map(e => `<li><code>${escHtml(e.from)}</code> → <code>${escHtml(e.to)}</code></li>`).join('') + '</ul>');

  // Cross-file calls
  if ((graph.call_edges || []).length) blocks.push('<h3>Cross-file calls</h3><ul>' + graph.call_edges.slice(0, 80).map(e => `<li><code>${escHtml(e.from)}</code> calls <b>${escHtml(e.function)}</b> in <code>${escHtml(e.to)}</code></li>`).join('') + '</ul>');

  // Data flow candidates
  if ((graph.dataflow_candidates || []).length) blocks.push('<h3>Source → Sink paths (heuristic)</h3><ul>' + graph.dataflow_candidates.slice(0, 50).map(f => `<li><code>${escHtml(f.source_file)}</code> lines ${escHtml((f.source_lines || []).join(', '))} → <code>${escHtml(f.sink_file)}</code> lines ${escHtml((f.sink_lines || []).join(', '))} <span class="sev-badge sev-badge--medium">${escHtml(f.confidence)}</span><p>${escHtml(f.note)}</p></li>`).join('') + '</ul>');

  if (!blocks.length) blocks.push('<p>No local import/call/data-flow relationships were identified.</p>');
  projectGraphDetails.innerHTML = blocks.join('');
  document.getElementById('project-graph-limitations').textContent = graph.limitations || 'Relationships are heuristic and should be reviewed.';
}

// ─── Vuln list ────────────────────────────────────────────────────────────────
function renderVulnList(vulns) {
  vulnList.innerHTML = '';
  vulns.forEach((v, idx) => vulnList.appendChild(createVulnCard(v, idx)));
  currentFilter = 'all';
  document.querySelectorAll('.pill').forEach(p => p.classList.toggle('pill--active', p.dataset.filter === 'all'));
}

function createVulnCard(v, idx) {
  const sev = (v.severity || 'LOW').toLowerCase();
  const card = document.createElement('div');
  card.className = `vuln-card vuln-card--${sev} animate-in`;
  card.style.animationDelay = `${idx * 40}ms`;
  card.dataset.severity = v.severity;

  const ruleName = v.rule_violated || v.title || v.category || 'Security Issue';
  const evidenceHtml = v.evidence ? `
    <div class="evidence-box">
      <div class="evidence-label">Vulnerable Code Snippet (Line ${escHtml(v.line)})</div>
      <div class="evidence-code">${escHtml(v.evidence)}</div>
    </div>` : '';
  const impactHtml = v.impact ? `
    <div class="impact-box">
      <div class="impact-label">⚠ Potential Impact</div>
      <div class="impact-text">${escHtml(v.impact)}</div>
    </div>` : '';

  const filePath = v.file || currentAnalysisData?.filename || '';
  const fileLabel = filePath ? escHtml(filePath) + ' · ' : '';
  const agentName = v.agent || (v.confidence >= 0.9 ? 'Deterministic AST Analyzer' : 'Groq Security Agent');
  const agentBadge = `<span class="vuln-agent-badge" title="Detected by ${escHtml(agentName)}">🤖 ${escHtml(agentName)}</span>`;

  card.innerHTML = `
    <div class="vuln-header">
      <span class="sev-badge sev-badge--${sev}">${escHtml(v.severity)}</span>
      <span class="vuln-id">${escHtml(v.id || '')}</span>
      <span class="vuln-rule">${escHtml(v.category || 'Security')} · ${escHtml(ruleName)}</span>
      ${agentBadge}
      <button type="button" class="vuln-jump-btn" title="Open file and jump to line ${escHtml(v.line)} in editor">
        ↗ ${fileLabel}Line ${escHtml(v.line)}
      </button>
      <svg class="vuln-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
    </div>
    <div class="vuln-body">
      <div class="desc-box"><b>Explanation:</b> ${escHtml(v.description || v.title || '')}</div>
      ${evidenceHtml}
      ${impactHtml}
      <div class="detail-grid">
        <div class="detail-item"><div class="detail-label">Vulnerability</div><div class="detail-value">${escHtml(ruleName)}</div></div>
        <div class="detail-item"><div class="detail-label">Responsible Agent</div><div class="detail-value">${escHtml(agentName)}</div></div>
        <div class="detail-item"><div class="detail-label">Confidence</div><div class="detail-value">${Math.round((Number(v.confidence ?? 0) || 0) * 100)}%</div></div>
        <div class="detail-item"><div class="detail-label">File &amp; Line</div><div class="detail-value">${filePath ? escHtml(filePath) + ':' : ''}${escHtml(v.line)}</div></div>
        <div class="detail-item"><div class="detail-label">Sink</div><div class="detail-value">${escHtml(v.sink || '—')}</div></div>
        <div class="detail-item"><div class="detail-label">Category</div><div class="detail-value">${escHtml(v.category || 'Security')}</div></div>
      </div>
      <div class="fix-box"><div class="fix-label">✦ Recommended Fix</div><div class="fix-text">${escHtml(v.suggested_fix || v.recommendation || '')}</div></div>
    </div>`;

  const jumpBtn = card.querySelector('.vuln-jump-btn');
  if (jumpBtn) {
    jumpBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      navigateToLine(filePath, v.line);
    });
  }

  card.querySelector('.vuln-header').addEventListener('click', (e) => {
    if (e.target.closest('.vuln-jump-btn')) return;
    card.classList.toggle('expanded');
  });
  return card;
}

document.getElementById('filter-pills').addEventListener('click', e => {
  const pill = e.target.closest('.pill');
  if (!pill) return;
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('pill--active'));
  pill.classList.add('pill--active');
  currentFilter = pill.dataset.filter;
  applyFilter();
});

function applyFilter() {
  document.querySelectorAll('.vuln-card').forEach(card => {
    card.classList.toggle('hidden', currentFilter !== 'all' && card.dataset.severity !== currentFilter);
  });
}

// ─── Symbol table ─────────────────────────────────────────────────────────────
function renderSymbolTable(symbolMap) {
  symbolBody.innerHTML = '';
  const entries = Object.entries(symbolMap);
  if (!entries.length) { symbolBody.innerHTML = '<tr><td colspan="2" style="color:var(--text-muted);text-align:center;padding:16px">No variables tracked</td></tr>'; return; }
  entries.sort(([, a], [, b]) => { const order = { TAINTED: 0, UNKNOWN: 1, SANITIZED: 2, UNTAINTED: 3 }; return (order[a] ?? 9) - (order[b] ?? 9); });
  entries.forEach(([name, state]) => {
    const stateStr = (typeof state === 'string' ? state : state.value || String(state)).toUpperCase();
    const row = document.createElement('tr');
    row.innerHTML = `<td>${escHtml(name)}</td><td><span class="taint-badge taint-badge--${taintClass(stateStr)}">${escHtml(stateStr)}</span></td>`;
    symbolBody.appendChild(row);
  });
}
function taintClass(state) { return state === 'TAINTED' ? 'tainted' : state === 'UNTAINTED' ? 'untainted' : state === 'SANITIZED' ? 'sanitized' : 'unknown'; }

let symbolCollapsed = false;
toggleSymbol.addEventListener('click', () => {
  symbolCollapsed = !symbolCollapsed;
  symbolWrap.classList.toggle('collapsed', symbolCollapsed);
  toggleSymbol.textContent = symbolCollapsed ? 'Expand' : 'Collapse';
});

// ─── Stats ────────────────────────────────────────────────────────────────────
function renderStats(stats) {
  statsGrid.innerHTML = '';
  const skip = new Set(['file_sources', 'project_graph']);  // skip large nested objects
  Object.entries(stats).forEach(([key, val]) => {
    if (skip.has(key) || typeof val === 'object') return;
    const item = document.createElement('div'); item.className = 'stat-item animate-in';
    item.innerHTML = `<div class="stat-key">${escHtml(key.replace(/_/g, ' '))}</div><div class="stat-val">${escHtml(String(val))}</div>`;
    statsGrid.appendChild(item);
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showToast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast--${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ─── Init ─────────────────────────────────────────────────────────────────────
updateEditorState();
updateLanguageUI();

// ─── Visual Side-by-Side Split Diff (Feature 4) ──────────────────────────────
function computeLineDiff(originalText, repairedText) {
  const origLines = (originalText || '').split('\n');
  const repLines = (repairedText || '').split('\n');
  const m = origLines.length;
  const n = repLines.length;

  if (m * n > 400000) {
    const pairs = [];
    const maxLen = Math.max(m, n);
    for (let i = 0; i < maxLen; i++) {
      const orig = i < m ? origLines[i] : null;
      const rep = i < n ? repLines[i] : null;
      const same = orig !== null && rep !== null && orig === rep;
      pairs.push({
        origNum: orig !== null ? i + 1 : '',
        origText: orig !== null ? orig : '',
        origType: same ? 'same' : (orig !== null ? 'del' : 'empty'),
        repNum: rep !== null ? i + 1 : '',
        repText: rep !== null ? rep : '',
        repType: same ? 'same' : (rep !== null ? 'add' : 'empty'),
      });
    }
    return pairs;
  }

  const dp = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (origLines[i - 1] === repLines[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  let i = m, j = n;
  const rawPairs = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && origLines[i - 1] === repLines[j - 1]) {
      rawPairs.push({
        origNum: i,
        origText: origLines[i - 1],
        origType: 'same',
        repNum: j,
        repText: repLines[j - 1],
        repType: 'same',
      });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      rawPairs.push({
        origNum: '',
        origText: '',
        origType: 'empty',
        repNum: j,
        repText: repLines[j - 1],
        repType: 'add',
      });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      rawPairs.push({
        origNum: i,
        origText: origLines[i - 1],
        origType: 'del',
        repNum: '',
        repText: '',
        repType: 'empty',
      });
      i--;
    }
  }
  rawPairs.reverse();

  // Consolidate adjacent deletions and additions into aligned modified rows
  const aligned = [];
  for (let idx = 0; idx < rawPairs.length; idx++) {
    const cur = rawPairs[idx];
    if (cur.origType === 'del' && idx + 1 < rawPairs.length && rawPairs[idx + 1].repType === 'add') {
      const next = rawPairs[idx + 1];
      aligned.push({
        origNum: cur.origNum,
        origText: cur.origText,
        origType: 'del',
        repNum: next.repNum,
        repText: next.repText,
        repType: 'add',
      });
      idx++;
    } else {
      aligned.push(cur);
    }
  }
  return aligned;
}

function renderSplitDiff(originalCode, repairedCode) {
  const origPane = document.getElementById('split-diff-orig');
  const repPane = document.getElementById('split-diff-rep');
  if (!origPane || !repPane) return;

  origPane.innerHTML = '';
  repPane.innerHTML = '';

  const pairs = computeLineDiff(originalCode, repairedCode);

  pairs.forEach(p => {
    // Left pane (original)
    const leftLine = document.createElement('div');
    leftLine.className = `diff-line ${p.origType === 'del' ? 'diff-line--del' : (p.origType === 'empty' ? 'diff-line--empty' : '')}`;
    const leftNum = document.createElement('span');
    leftNum.className = 'diff-num';
    leftNum.textContent = p.origNum;
    const leftMarker = document.createElement('span');
    leftMarker.className = 'diff-marker';
    leftMarker.textContent = p.origType === 'del' ? '-' : (p.origType === 'same' ? ' ' : '');
    const leftCode = document.createElement('span');
    leftCode.className = 'diff-code';
    leftCode.textContent = p.origText;
    leftLine.appendChild(leftNum);
    leftLine.appendChild(leftMarker);
    leftLine.appendChild(leftCode);
    origPane.appendChild(leftLine);

    // Right pane (repaired)
    const rightLine = document.createElement('div');
    rightLine.className = `diff-line ${p.repType === 'add' ? 'diff-line--add' : (p.repType === 'empty' ? 'diff-line--empty' : '')}`;
    const rightNum = document.createElement('span');
    rightNum.className = 'diff-num';
    rightNum.textContent = p.repNum;
    const rightMarker = document.createElement('span');
    rightMarker.className = 'diff-marker';
    rightMarker.textContent = p.repType === 'add' ? '+' : (p.repType === 'same' ? ' ' : '');
    const rightCode = document.createElement('span');
    rightCode.className = 'diff-code';
    rightCode.textContent = p.repText;
    rightLine.appendChild(rightNum);
    rightLine.appendChild(rightMarker);
    rightLine.appendChild(rightCode);
    repPane.appendChild(rightLine);
  });

  // Synchronized scrolling
  let isScrolling = false;
  origPane.onscroll = () => {
    if (!isScrolling) {
      isScrolling = true;
      repPane.scrollTop = origPane.scrollTop;
      repPane.scrollLeft = origPane.scrollLeft;
      requestAnimationFrame(() => { isScrolling = false; });
    }
  };
  repPane.onscroll = () => {
    if (!isScrolling) {
      isScrolling = true;
      origPane.scrollTop = repPane.scrollTop;
      origPane.scrollLeft = repPane.scrollLeft;
      requestAnimationFrame(() => { isScrolling = false; });
    }
  };
}

// Split diff view toggle
const btnSplit = document.getElementById('diff-view-split');
const btnUnified = document.getElementById('diff-view-unified');
const splitDiffView = document.getElementById('split-diff-view');
const unifiedCodeView = document.getElementById('unified-code-view');

if (btnSplit && btnUnified) {
  btnSplit.onclick = () => {
    btnSplit.classList.add('active');
    btnUnified.classList.remove('active');
    if (splitDiffView) splitDiffView.hidden = false;
    if (unifiedCodeView) unifiedCodeView.hidden = true;
  };
  btnUnified.onclick = () => {
    btnUnified.classList.add('active');
    btnSplit.classList.remove('active');
    if (splitDiffView) splitDiffView.hidden = true;
    if (unifiedCodeView) unifiedCodeView.hidden = false;
  };
}

// ─── Dependencies / SCA Scanner (Feature 2) ─────────────────────────
async function runDependencyScan() {
  const editor = document.getElementById('sca-editor');
  const nameInput = document.getElementById('sca-manifest-name');
  if (!editor || !nameInput) return;

  const content = editor.value.trim();
  const filename = nameInput.value.trim() || 'requirements.txt';
  const resultsList = document.getElementById('sca-results-list');

  if (!content) {
    showToast('Please paste requirements.txt or package.json content to scan.', 'error');
    return;
  }

  resultsList.innerHTML = '<p class="drop-zone-hint">Scanning dependencies for CVE vulnerabilities…</p>';

  try {
    const res = await fetch(`${API_BASE}/scan-dependencies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, filename })
    });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.error || 'Dependency scan failed');

    renderScaResults(data);
  } catch (err) {
    resultsList.innerHTML = `<div class="error-msg">Scan error: ${escHtml(err.message)}</div>`;
  }
}

function renderScaResults(data) {
  const badge = document.getElementById('sca-status-badge');
  const metrics = document.getElementById('sca-metrics-bar');
  const upgradesSec = document.getElementById('sca-upgrades-section');
  const upgradesPre = document.getElementById('sca-upgrade-commands');
  const resultsList = document.getElementById('sca-results-list');

  if (badge) {
    badge.hidden = false;
    if (data.status === 'CLEAN') {
      badge.className = 'syntax-badge syntax-badge--ok';
      badge.textContent = `✓ Clean (${data.total_dependencies} Packages)`;
    } else {
      badge.className = 'syntax-badge syntax-badge--warn';
      badge.textContent = `⚠ ${data.total_cves} CVEs (${data.vulnerable_count} Vulnerable)`;
    }
  }

  if (metrics) metrics.hidden = false;
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl('sca-total-pkgs', data.total_dependencies || 0);
  setEl('sca-crit-cves', data.severity_summary?.CRITICAL || 0);
  setEl('sca-high-cves', data.severity_summary?.HIGH || 0);
  setEl('sca-med-cves', data.severity_summary?.MEDIUM || 0);
  setEl('sca-vuln-pkgs', data.vulnerable_count || 0);

  if (upgradesSec && upgradesPre) {
    if (data.upgrade_commands && data.upgrade_commands.length > 0) {
      upgradesSec.hidden = false;
      upgradesPre.textContent = data.upgrade_commands.join('\n');
    } else {
      upgradesSec.hidden = true;
    }
  }

  if (resultsList) {
    resultsList.innerHTML = '';
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      resultsList.innerHTML = '<div style="padding:16px; background:rgba(34,197,94,0.1); border:1px solid #22c55e; border-radius:8px; color:#4ade80;">✓ All packages are at secure, non-vulnerable versions! No known CVE advisories found.</div>';
      return;
    }

    data.vulnerabilities.forEach(v => {
      const card = document.createElement('div');
      card.className = 'sca-cve-card';
      card.innerHTML = `
        <div class="sca-cve-head">
          <span class="sca-cve-title">${escHtml(v.package)}: ${escHtml(v.title)}</span>
          <div class="sca-cve-badges">
            <span class="sca-badge sca-badge--${(v.severity || 'low').toLowerCase()}">${escHtml(v.severity)} · CVSS ${escHtml(String(v.cvss))}</span>
            <a href="${escHtml(v.advisory_url)}" target="_blank" rel="noopener" style="font-size:11px; color:#38bdf8; text-decoration:underline;">${escHtml(v.cve)} ↗</a>
          </div>
        </div>
        <div class="sca-cve-desc">${escHtml(v.description)}</div>
        <div class="sca-cve-meta">
          <span>Installed: <code style="color:#f87171;">${escHtml(v.installed_version)}</code></span>
          <span>Secure Version: <span class="sca-upgrade-pill">>= ${escHtml(v.fixed_version)}</span></span>
          <span>Manifest Line: <code>${escHtml(v.manifest_line)}</code></span>
        </div>
      `;
      resultsList.appendChild(card);
    });
  }
}

// Wire SCA Buttons
const scaScanBtn = document.getElementById('sca-scan-btn');
if (scaScanBtn) scaScanBtn.onclick = runDependencyScan;

const sampleReqsBtn = document.getElementById('sca-sample-reqs');
if (sampleReqsBtn) {
  sampleReqsBtn.onclick = () => {
    const nameEl = document.getElementById('sca-manifest-name');
    const edEl = document.getElementById('sca-editor');
    if (nameEl) nameEl.value = 'requirements.txt';
    if (edEl) edEl.value = `requests==2.20.0\nurllib3==1.24.2\njinja2==3.0.0\npyyaml==5.3\ncertifi>=2024.1.1`;
    runDependencyScan();
  };
}

const samplePkgBtn = document.getElementById('sca-sample-pkg');
if (samplePkgBtn) {
  samplePkgBtn.onclick = () => {
    const nameEl = document.getElementById('sca-manifest-name');
    const edEl = document.getElementById('sca-editor');
    if (nameEl) nameEl.value = 'package.json';
    if (edEl) edEl.value = JSON.stringify({
      "name": "my-secure-app",
      "dependencies": {
        "lodash": "^4.17.15",
        "axios": "0.21.0",
        "jsonwebtoken": "8.5.1",
        "minimist": "1.2.5"
      }
    }, null, 2);
    runDependencyScan();
  };
}

const copyUpgradesBtn = document.getElementById('copy-all-upgrades-btn');
if (copyUpgradesBtn) {
  copyUpgradesBtn.onclick = () => {
    const text = document.getElementById('sca-upgrade-commands')?.textContent || '';
    navigator.clipboard.writeText(text).then(() => {
      copyUpgradesBtn.textContent = '✓ Copied!';
      setTimeout(() => { copyUpgradesBtn.textContent = '📋 Copy Commands'; }, 2000);
    });
  };
}

// ─── MULTI-AGENT DASHBOARD & ORCHESTRATION (Sections 9 & 10) ────────────────
let currentRoutingMode = 'AUTO';

async function fetchAgentsAndActivity() {
  try {
    const [agentsRes, actRes] = await Promise.all([
      fetch(`${API_BASE}/api/agents`).then(r => r.json()),
      fetch(`${API_BASE}/api/agent-activity`).then(r => r.json())
    ]);

    if (agentsRes.success) {
      currentRoutingMode = agentsRes.routing_mode || 'AUTO';
      updateRoutingModeUI(currentRoutingMode);
      renderRegisteredAgents(agentsRes.agents || []);
    }

    if (actRes.success) {
      renderAgentActivities(actRes.activities || []);
    }
  } catch (err) {
    console.warn('Could not fetch agent dashboard data:', err);
  }
}

function updateRoutingModeUI(mode) {
  currentRoutingMode = mode;
  document.querySelectorAll('#routing-mode-group .mode-pill').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });
}

function renderRegisteredAgents(agents) {
  const container = document.getElementById('agents-grid-container');
  if (!container) return;
  container.innerHTML = '';

  let waitingCount = 0;
  agents.forEach(agent => {
    if (agent.available) waitingCount++;
    const card = document.createElement('div');
    card.className = `agent-card${agent.available ? '' : ' offline'}`;
    const modeClass = agent.execution_mode === 'ONLINE_AI' ? 'badge-cloud' : (agent.execution_mode === 'LOCAL_AI' ? 'badge-local' : 'badge-static');
    const modeLabel = agent.execution_mode === 'ONLINE_AI' ? '☁ Cloud AI' : (agent.execution_mode === 'LOCAL_AI' ? '💻 Ollama Local' : '⚙ Local Static');
    const statusDot = agent.available ? '<span class="stat-indicator dot-green" title="Ready / Waiting"></span>' : '<span class="stat-indicator dot-red" title="Disabled / Offline"></span>';

    card.innerHTML = `
      <div class="agent-card-header">
        <span class="agent-card-title">${statusDot} ${escHtml(agent.name)}</span>
        <span class="agent-badge-mode ${modeClass}">${modeLabel}</span>
      </div>
      <div class="agent-card-role">${escHtml(agent.role)}</div>
      <div class="agent-card-meta">Model: ${escHtml(agent.model_name)}</div>
    `;
    container.appendChild(card);
  });

  const waitingEl = document.getElementById('stat-waiting-agents');
  if (waitingEl) waitingEl.textContent = waitingCount;
  const readyBadge = document.getElementById('agents-ready-badge');
  if (readyBadge) readyBadge.textContent = `${agents.length} Total · ${waitingCount} Ready`;
}

function renderAgentActivities(activities) {
  const listEl = document.getElementById('agent-activity-list');
  const countBadge = document.getElementById('activity-count-badge');
  if (!listEl) return;
  listEl.innerHTML = '';

  if (!activities || !activities.length) {
    listEl.innerHTML = '<div class="activity-empty">No agent tasks executed yet. Run an analysis, explanation, or repair to observe live multi-agent execution.</div>';
    if (countBadge) countBadge.textContent = '0 logged tasks';
    return;
  }

  if (countBadge) countBadge.textContent = `${activities.length} logged task${activities.length === 1 ? '' : 's'}`;

  let activeCount = 0;
  let completedCount = 0;
  let failedCount = 0;

  activities.forEach(act => {
    if (act.status === 'RUNNING') activeCount++;
    else if (act.status === 'COMPLETED') completedCount++;
    else if (act.status === 'FAILED') failedCount++;

    const card = document.createElement('div');
    card.className = 'activity-card';

    const dotColor = act.status === 'COMPLETED' ? 'dot-green' : (act.status === 'RUNNING' ? 'dot-blue' : (act.status === 'FAILED' ? 'dot-red' : 'dot-yellow'));
    const handoffHtml = act.handoff_to ? `<span class="activity-handoff-tag">➔ Handoff: ${escHtml(act.handoff_to)}</span>` : '';
    const detailsJson = JSON.stringify(act.details || {}, null, 2);

    card.innerHTML = `
      <div class="activity-card-header">
        <span class="stat-indicator ${dotColor}"></span>
        <span class="activity-agent-name">${escHtml(act.agent_name)}</span>
        <span class="badge-tag">${escHtml(act.task_type)}</span>
        ${handoffHtml}
        <span class="activity-time-stamp">${escHtml(act.timestamp)} · ${act.execution_time_ms} ms</span>
      </div>
      <div class="activity-card-meta">
        <span>Mode: <b>${escHtml(act.execution_mode)}</b></span>
        <span>Model: <b>${escHtml(act.model_used)}</b></span>
        <span>Findings: <b>${act.findings_count}</b></span>
        <span style="margin-left:auto; cursor:pointer; color:var(--primary);">Details ▾</span>
      </div>
      <div class="activity-details-drawer">${escHtml(detailsJson)}</div>
    `;

    card.onclick = () => card.classList.toggle('expanded');
    listEl.appendChild(card);
  });

  const activeEl = document.getElementById('stat-active-agents');
  if (activeEl) activeEl.textContent = activeCount;
  const compEl = document.getElementById('stat-completed-agents');
  if (compEl) compEl.textContent = completedCount;
  const failEl = document.getElementById('stat-failed-agents');
  if (failEl) failEl.textContent = failedCount;
}

// Mode Selector Listeners
document.querySelectorAll('#routing-mode-group .mode-pill').forEach(btn => {
  btn.addEventListener('click', async () => {
    const mode = btn.dataset.mode;
    try {
      const res = await fetch(`${API_BASE}/api/config/routing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      }).then(r => r.json());
      if (res.success) {
        updateRoutingModeUI(mode);
        showToast(`Switched execution policy to: ${mode}`, 'success');
        fetchAgentsAndActivity();
      }
    } catch (err) {
      showToast(`Could not switch mode: ${err.message}`, 'error');
    }
  });
});

// Quick Orchestrator Actions
document.getElementById('btn-run-self-healing')?.addEventListener('click', async () => {
  const code = codeEditor.value;
  if (!code.trim()) { showToast('Write or open code in the editor first.', 'warning'); return; }
  const btn = document.getElementById('btn-run-self-healing');
  btn.disabled = true;
  btn.textContent = '⚡ Running Pipeline…';
  showToast('Orchestrating 11-step Self-Healing Pipeline...', 'info');
  try {
    const res = await fetch(`${API_BASE}/api/orchestrate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'self_healing', code, filename: sourceName.value })
    }).then(r => r.json());

    if (res.success && res.repaired_code) {
      aiRepairResult = {
        repaired_code: res.repaired_code,
        explanation: res.repair_explanation,
        filename: res.filename,
        verified: res.verified
      };
      document.getElementById('ai-repaired-code').textContent = res.repaired_code;
      renderSplitDiff(code, res.repaired_code);
      const reviewSec = document.getElementById('ai-review-section');
      if (reviewSec) reviewSec.hidden = false;
      showPane('results');
      const vStatus = res.verified ? 'Verified: Clean & compiles' : 'Validation pending';
      showToast(`Self-healing completed (${vStatus})! Review the split diff.`, 'success');
    } else {
      showToast(res.message || 'Self-healing finished with no modifications needed.', 'info');
    }
    fetchAgentsAndActivity();
  } catch (err) {
    showToast(`Pipeline failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '⚡ Run Self-Healing Pipeline';
  }
});

document.getElementById('btn-explain-active')?.addEventListener('click', async () => {
  const code = codeEditor.value;
  if (!code.trim()) { showToast('Write or open code in the editor first.', 'warning'); return; }
  showToast('CodeExplanationAgent analyzing file...', 'info');
  try {
    const res = await fetch(`${API_BASE}/api/orchestrate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'explain', code, filename: sourceName.value })
    }).then(r => r.json());

    const expText = res.recommendation || res.data?.explanation || 'Explanation generated.';
    alert(`💡 Code Explanation (${res.model_used}):\n\n${expText}`);
    fetchAgentsAndActivity();
  } catch (err) {
    showToast(`Explanation failed: ${err.message}`, 'error');
  }
});

document.getElementById('btn-verify-current')?.addEventListener('click', async () => {
  const code = codeEditor.value;
  if (!code.trim()) { showToast('Write or open code in the editor first.', 'warning'); return; }
  showToast('VerificationAgent testing code...', 'info');
  try {
    const res = await fetch(`${API_BASE}/api/orchestrate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'verify', code, filename: sourceName.value })
    }).then(r => r.json());

    const vOk = res.data?.verified;
    showToast(`Verification result: ${vOk ? 'PASSED (0 syntax errors)' : 'FAILED issues detected'}`, vOk ? 'success' : 'error');
    fetchAgentsAndActivity();
  } catch (err) {
    showToast(`Verification failed: ${err.message}`, 'error');
  }
});

document.getElementById('btn-refresh-agents')?.addEventListener('click', () => {
  fetchAgentsAndActivity();
  showToast('Refreshed agents and activity log.');
});

// Trigger fetch when Agents pane is selected
document.querySelectorAll('.pane-tab[data-pane="agents"], .nav-link[data-pane="agents"]').forEach(el => {
  el.addEventListener('click', () => {
    fetchAgentsAndActivity();
  });
});

// Initial load
fetchAgentsAndActivity();
