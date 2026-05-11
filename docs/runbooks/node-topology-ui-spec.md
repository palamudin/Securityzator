# Securityzator Node Topology UI Spec

Last reviewed: `2026-04-24`

## Goal

Define a buildable UI block for Securityzator that presents recommendation groups and controls as a node topology or terrain-like plane instead of a flat card list.

This spec exists to keep the frontend grounded in real product meaning and data, while still allowing visual exploration and iterative design work.

## Core concept

Securityzator should present the tenant security surface as a landscape:

- each node represents a recommendation or control anchor
- related nodes cluster into a group
- groups form larger product families like `Defender`, `Endpoint`, `Entra`, `Exchange`, `Teams`, and later `AD`
- node height reflects state or score coverage on a `0-100` scale
- node color reflects status
- links show relationship and grouping, not decorative noise

The topology block is an overview and exploration surface, not the only way to use the product.

## Important implementation decision

### Do not directly ship the CodePen as the product surface

Reference inspiration:

- `https://codepen.io/franky/pen/LGMWPK`

Why it is useful:

- nice visual language for mesh, glow, and connected-node atmosphere
- helpful starting point for motion feel and ambient background

Why it is not the final implementation model:

- it is a random 2D particle animation
- it spawns particles procedurally
- it is not state-driven
- it is not built around deterministic product data
- a rotatable plane with meaningful height is closer to a scene graph than a decorative particle field

Recommended read:

- use the CodePen as `visual inspiration`
- do **not** use it as the final behavior architecture

## Recommended technical direction

### Preferred

- `Three.js` or `react-three-fiber` style scene model
- deterministic positions generated from group and item data
- camera rotation and zoom as first-class interactions

### Acceptable fallback

- layered `canvas` or `SVG` with fake depth
- no full 3D camera, only tilt/parallax

### Avoid

- pure random particle network reused as app logic
- DOM-only hundreds-of-nodes layout with ad hoc transforms
- freehand animation with no stable data mapping

## Data sources

Primary mock data sources already available in repo:

- `artifacts/reports/recommendation-groups-summary.json`
- `artifacts/reports/recommendation-group-items.json`
- `artifacts/reports/recommendation-groups-tree.json`

Preferred runtime source for the topology block:

- `recommendation-groups-tree.json`

Why:

- groups already contain nested items
- each group already has:
  - `groupKey`
  - `groupStatus`
  - `recommendationCount`
  - `runnableCount`
  - `blockedCount`
  - `products`
  - `categories`
  - `deliveryModes`
  - `sampleTitle`
- each item already has:
  - `controlId`
  - `itemStatus`
  - `rank`
  - `title`
  - `product`
  - `category`
  - `classification`
  - `deliveryMode`
  - `supportsQueue`
  - `isEndpointFamily`

## Visual semantics

### Group level

- `green`
  - all controls in group are runnable/live-capable
- `amber`
  - mixed or partial coverage
- `red`
  - no controls in group are currently runnable

### Node height

Suggested mapping:

- group height = percent of controls in that group that are runnable
- item height = importance/rank weighting or readiness weighting

Simple formula for group height:

- `height = (runnableCount / recommendationCount) * 100`

### Links

- links inside a group should be denser and brighter
- links across groups should be thinner and less prominent
- family-level parent links should visually anchor group clusters into one plane

### Labels

- do not label every item in the scene
- label only:
  - selected node
  - hovered node
  - major group peaks

## Required blocks

### 1. Collapsible sidebar

Requirements:

- left-aligned
- collapsible
- logo at top
- dark/light theme switch below the logo
- six placeholder menu items
- two menu items with dropdown children

This sidebar is product shell, not part of the topology scene itself.

### 2. Topology viewport

Requirements:

- main content block
- supports drag rotation
- supports zoom or at least scale depth
- upper-right floating control cluster inside the content area

Control cluster should support:

- `All / Identity / Apps / Endpoint / AD` filters
- `Group view / Item view`
- `Green / Amber / Red` visibility toggles
- `Reset camera`

### 3. Hover/click detail surface

Requirements:

- hover preview for quick signal
- click opens richer detail
- should be a hovering modal, popover, or right-side drawer

Minimum detail content:

- title
- group
- current status
- control counts
- delivery mode
- actionable state buttons:
  - `On`
  - `Report only`
  - `Clean`

Important:

- these buttons should be real product actions only when fully wired
- until then, they should be clearly marked as placeholders or disabled

### 4. Fallback list/table

Requirements:

- traditional operator-safe fallback below or beside the map
- same data as the topology
- searchable/filterable list

Why:

- the topology is a discovery surface
- the fallback list is the dependable work surface

## Interaction model

### Hover

Hover should show:

- group name or control title
- status color
- total controls
- runnable vs blocked
- sample title or first few items

### Click

Click should:

- pin selection
- open detail drawer or modal
- highlight related nodes/links

### Drag

Drag should:

- rotate the plane
- never spawn new points

### Disabled behavior from the inspiration pen

Must remove:

- click-to-spawn points
- random particle creation
- purely decorative drift that breaks node readability

## Layout principles

- treat the topology as a hero block, not the whole page
- keep explanatory text minimal
- lead with signal, counts, and action
- avoid burying the operator in paragraphs
- support keyboard and non-WebGL fallback where possible

## Enterprise maintainability requirements

- stable IDs and classes for interactive controls
- clean separation between:
  - visual scene layer
  - sidebar shell
  - detail drawer
  - real action wiring
- no hard-coded fantasy statuses in templates
- no “pretty mock buttons” pretending to be live actions
- every live action must map back to a real route or API surface

## Build phases

### Phase 1. Static block

- sidebar shell
- topology viewport shell
- floating controls shell
- right-side detail drawer
- bind only to mock JSON
- no live action buttons yet

### Phase 2. Interactive mock

- deterministic node placement
- drag/rotate/zoom
- hover and click details
- filters by product/category/status
- fallback list synchronized with selection

### Phase 3. Product wiring

- connect to real backend recommendation payload
- map statuses to real remediation state
- wire only the actions that already exist in product
- leave unsupported actions visibly disabled

### Phase 4. Operational polish

- responsive behavior
- accessibility pass
- performance tuning for larger graphs
- state restoration and deep-linking

## Prompting contract for design-model help

If using a design-oriented model for ideation, keep the prompt constrained:

- ask for `layout and styling only`
- explicitly forbid inventing routes, behaviors, or fake states
- require preservation of:
  - sidebar structure
  - topology viewport
  - hover/click detail surface
  - fallback list area
- require that every interactive affordance be marked as:
  - `wired`
  - `placeholder`
  - `disabled`

### Safer prompt frame

> Create a frontend layout concept for a security topology page.
> Use a deterministic node-map viewport inspired by connected mesh landscapes.
> Do not invent backend behavior.
> Do not remove existing interaction placeholders.
> Preserve the following blocks exactly:
> collapsible sidebar, theme switch, topology viewport, floating filters, detail drawer, fallback list.
> Treat all action buttons as disabled placeholders unless specifically marked as wired.

## First implementation recommendation

Start with:

- one page
- one topology block
- mock data from `recommendation-groups-tree.json`
- only group-level nodes first

Do **not** start with:

- 440 fully rendered item nodes at once
- real remediation action wiring inside the first visual prototype
- random particle motion as the main interaction model

## Definition of success

The first good version should let an operator:

1. see group clusters clearly
2. distinguish green/amber/red status instantly
3. rotate and inspect the map without losing orientation
4. click a group and see meaningful detail
5. fall back to a conventional list immediately when they want to work

If it looks amazing but breaks those five things, it is not the right build.
