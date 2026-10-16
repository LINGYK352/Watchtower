import catalog from './pageGuides.json'
export interface GuideStep { key:string; selector:string }
export const pageGuides:Record<string,GuideStep[]>=catalog
