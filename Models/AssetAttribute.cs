using System;

namespace PhotosManager.Models
{
    public class AssetAttribute : Attribute
    {
        private readonly string folder;
        private readonly string defaultValue;

        public AssetAttribute(string folder, string defaultValue)
        {
            this.folder = folder;
            this.defaultValue = defaultValue;
        }
        public string Folder() => folder;
        public string DefaultValue() => defaultValue;
    }
}