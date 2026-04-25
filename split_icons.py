#!/usr/bin/env python3
"""
Parse file.svg, find distinct icon clusters by analyzing path bounding boxes,
and export each cluster as a separate cropped square SVG icon.
"""

import xml.etree.ElementTree as ET
import re
import os
from collections import defaultdict

def parse_path_bbox(d_attr):
    """Extract approximate bounding box from an SVG path d attribute by parsing coordinates."""
    if not d_attr:
        return None
    
    # Extract all numbers from the path data
    # Match numbers including decimals and negatives
    numbers = re.findall(r'-?\d+\.?\d*', d_attr)
    if len(numbers) < 2:
        return None
    
    # Parse coordinates - SVG path commands use x,y pairs
    # We'll extract all numbers and treat consecutive pairs as coordinates
    coords = [float(n) for n in numbers]
    
    # Filter out obviously wrong values (indices, flags, etc.)
    # Focus on values that are within the 0-2048 viewBox range
    xs = []
    ys = []
    
    # Simple approach: scan through path commands
    # M, L, C, S, Q, T commands use absolute coordinates
    # Extract command letters and their parameters
    commands = re.findall(r'([MmLlHhVvCcSsQqTtAaZz])\s*((?:[^MmLlHhVvCcSsQqTtAaZz])*)', d_attr)
    
    cur_x, cur_y = 0, 0
    
    for cmd, params in commands:
        nums = [float(n) for n in re.findall(r'-?\d+\.?\d*', params)]
        
        if cmd == 'M':
            i = 0
            while i + 1 < len(nums):
                cur_x, cur_y = nums[i], nums[i+1]
                xs.append(cur_x)
                ys.append(cur_y)
                i += 2
        elif cmd == 'm':
            i = 0
            while i + 1 < len(nums):
                if i == 0:
                    cur_x += nums[i]
                    cur_y += nums[i+1]
                else:
                    cur_x += nums[i]
                    cur_y += nums[i+1]
                xs.append(cur_x)
                ys.append(cur_y)
                i += 2
        elif cmd == 'L':
            i = 0
            while i + 1 < len(nums):
                cur_x, cur_y = nums[i], nums[i+1]
                xs.append(cur_x)
                ys.append(cur_y)
                i += 2
        elif cmd == 'l':
            i = 0
            while i + 1 < len(nums):
                cur_x += nums[i]
                cur_y += nums[i+1]
                xs.append(cur_x)
                ys.append(cur_y)
                i += 2
        elif cmd == 'H':
            for n in nums:
                cur_x = n
                xs.append(cur_x)
        elif cmd == 'h':
            for n in nums:
                cur_x += n
                xs.append(cur_x)
        elif cmd == 'V':
            for n in nums:
                cur_y = n
                ys.append(cur_y)
        elif cmd == 'v':
            for n in nums:
                cur_y += n
                ys.append(cur_y)
        elif cmd == 'C':
            i = 0
            while i + 5 < len(nums):
                xs.extend([nums[i], nums[i+2], nums[i+4]])
                ys.extend([nums[i+1], nums[i+3], nums[i+5]])
                cur_x, cur_y = nums[i+4], nums[i+5]
                i += 6
        elif cmd == 'c':
            i = 0
            while i + 5 < len(nums):
                xs.extend([cur_x + nums[i], cur_x + nums[i+2], cur_x + nums[i+4]])
                ys.extend([cur_y + nums[i+1], cur_y + nums[i+3], cur_y + nums[i+5]])
                cur_x += nums[i+4]
                cur_y += nums[i+5]
                i += 6
        elif cmd in ('S', 'Q'):
            i = 0
            step = 4
            while i + step - 1 < len(nums):
                for j in range(0, step, 2):
                    xs.append(nums[i+j])
                    ys.append(nums[i+j+1])
                cur_x, cur_y = nums[i+step-2], nums[i+step-1]
                i += step
        elif cmd == 'Z' or cmd == 'z':
            pass
    
    if not xs or not ys:
        # Fallback: just grab all numbers as alternating x,y
        for i in range(0, len(coords) - 1, 2):
            if 0 <= coords[i] <= 2048 and 0 <= coords[i+1] <= 2048:
                xs.append(coords[i])
                ys.append(coords[i+1])
    
    if not xs or not ys:
        return None
    
    return (min(xs), min(ys), max(xs), max(ys))


def bbox_overlap(b1, b2, margin=30):
    """Check if two bounding boxes overlap (with margin for grouping nearby elements)."""
    return not (b1[2] + margin < b2[0] or b2[2] + margin < b1[0] or
                b1[3] + margin < b2[1] or b2[3] + margin < b1[1])


def merge_bboxes(b1, b2):
    """Merge two bounding boxes."""
    return (min(b1[0], b2[0]), min(b1[1], b2[1]),
            max(b1[2], b2[2]), max(b1[3], b2[3]))


def find_clusters(bboxes, margin=30):
    """Cluster overlapping bounding boxes using union-find."""
    n = len(bboxes)
    parent = list(range(n))
    
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    
    # Check all pairs for overlap
    for i in range(n):
        for j in range(i + 1, n):
            if bbox_overlap(bboxes[i], bboxes[j], margin):
                union(i, j)
    
    # Group by cluster
    clusters = defaultdict(list)
    for i in range(n):
        clusters[find(i)].append(i)
    
    return clusters


def main():
    svg_path = '/home/user/Desktop/static_store/file.svg'
    output_dir = '/home/user/Desktop/static_store/icons_split'
    os.makedirs(output_dir, exist_ok=True)
    
    print("Parsing SVG...")
    tree = ET.parse(svg_path)
    root = tree.getroot()
    
    # Handle namespace
    ns = ''
    if root.tag.startswith('{'):
        ns = root.tag.split('}')[0] + '}'
    
    # Collect all paths with their bounding boxes
    paths = []
    bboxes = []
    
    for elem in root.iter(f'{ns}path'):
        d = elem.get('d', '')
        bbox = parse_path_bbox(d)
        if bbox and (bbox[2] - bbox[0]) > 5 and (bbox[3] - bbox[1]) > 5:  # Skip tiny paths
            paths.append(elem)
            bboxes.append(bbox)
    
    print(f"Found {len(paths)} paths with valid bounding boxes")
    
    # Cluster paths that are near each other
    print("Clustering paths into icons...")
    clusters = find_clusters(bboxes, margin=20)
    
    # Calculate cluster bounding boxes
    cluster_bboxes = {}
    for root_id, members in clusters.items():
        merged = bboxes[members[0]]
        for m in members[1:]:
            merged = merge_bboxes(merged, bboxes[m])
        cluster_bboxes[root_id] = merged
    
    # Filter out very small clusters (noise) and the background
    # and very large clusters (full-page background)
    min_size = 50
    max_size = 1800  # if it spans almost the whole viewBox, it's background
    
    significant_clusters = {}
    for root_id, bbox in cluster_bboxes.items():
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        if w >= min_size and h >= min_size and w <= max_size and h <= max_size:
            significant_clusters[root_id] = {
                'bbox': bbox,
                'members': clusters[root_id],
                'width': w,
                'height': h
            }
    
    print(f"Found {len(significant_clusters)} significant icon clusters")
    
    # Sort by position (top-left to bottom-right)
    sorted_clusters = sorted(significant_clusters.items(), 
                             key=lambda x: (int(x[1]['bbox'][1] / 200), x[1]['bbox'][0]))
    
    # Print info about each cluster
    for i, (_root_id, info) in enumerate(sorted_clusters):
        bbox = info['bbox']
        print(f"  Icon {i+1}: bbox=({bbox[0]:.0f}, {bbox[1]:.0f}, {bbox[2]:.0f}, {bbox[3]:.0f}), "
              f"size={info['width']:.0f}x{info['height']:.0f}, paths={len(info['members'])}")

    # Export each cluster as a separate SVG
    for i, (_root_id, info) in enumerate(sorted_clusters):
        bbox = info['bbox']
        
        # Add padding
        padding = 10
        x = bbox[0] - padding
        y = bbox[1] - padding
        w = info['width'] + 2 * padding
        h = info['height'] + 2 * padding
        
        # Make it square (use the larger dimension)
        size = max(w, h)
        # Center the content in the square
        cx = x + w / 2
        cy = y + h / 2
        x = cx - size / 2
        y = cy - size / 2
        
        # Create new SVG with just this cluster's paths
        svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1"
     viewBox="{x:.1f} {y:.1f} {size:.1f} {size:.1f}"
     width="128" height="128">
'''
        
        for member_idx in info['members']:
            elem = paths[member_idx]
            # Reconstruct the path element
            attribs = ' '.join(f'{k}="{v}"' for k, v in elem.attrib.items())
            svg_content += f'  <path {attribs} />\n'
        
        svg_content += '</svg>\n'
        
        out_file = os.path.join(output_dir, f'icon_{i+1:02d}.svg')
        with open(out_file, 'w') as f:
            f.write(svg_content)
    
    print(f"\nExported {len(sorted_clusters)} icons to {output_dir}/")


if __name__ == '__main__':
    main()
