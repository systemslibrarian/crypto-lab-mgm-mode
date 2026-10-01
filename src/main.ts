import './style.css';
import { mountWorkbench } from './ui/workbench';
import { mountLimits, mountReuse, mountRfcCheck, mountSbox } from './ui/exhibits';

mountWorkbench();
mountRfcCheck();
mountReuse();
mountLimits();
mountSbox();
