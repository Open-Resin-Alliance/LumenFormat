import type { SlicingFormatDefinition } from '@/features/slicing/formats/types';

export const LUMEN_FORMAT_DEFINITION: SlicingFormatDefinition = {
  id: 'lumen.lumen.v1',
  outputFormat: '.lumen',
  displayName: 'LUMEN',
  ownership: 'plugin',
  layerDataKind: 'raw-mask',
  pluginId: 'lumen',
  formatVersions: [
    { value: 'v1', label: 'V1', isDefault: true }
  ],
  settingsModes: [
    { value: 'simple', label: 'Simple', isDefault: true },
    { value: 'twostage', label: 'Two Stage' },
    { value: 'tilting', label: 'Tilting Vat' },
    { value: 'allfields', label: 'All Fields Single Step Motion'}
  ],
  rustModulePath: 'formats::lumen',
  wasmExportName: 'encode_lumen_container',
  notes: 'Run-end encoded layer data compressed in zstd blocks, encoded by the LUMEN reference crate.',
};
