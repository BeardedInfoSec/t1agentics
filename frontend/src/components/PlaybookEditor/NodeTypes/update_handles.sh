#!/bin/bash
for file in ActionNode.js ConditionNode.js EnrichNode.js PythonCodeNode.js RiggsNode.js WebformNode.js; do
  # Add target handle (input) at the top
  sed -i '/<div style={styles\.handleIn}/c\      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />' "$file"
  
  # Add source handle (output) at the bottom  
  sed -i '/<div style={{.*styles\.handleOut/c\      <Handle type="source" position={Position.Bottom} id="output" style={styles.handle} />' "$file"
  sed -i '/<div style={styles\.handleOut}/c\      <Handle type="source" position={Position.Bottom} id="output" style={styles.handle} />' "$file"
  
  echo "Updated handles in $file"
done
