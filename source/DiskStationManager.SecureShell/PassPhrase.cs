using System;
using System.IO;
using System.Windows.Forms;

namespace DiskStationManager.SecureShell
{
    public partial class PassPhrase : Form
    {
        public bool Canceled { get; private set; } = true;
        internal PassPhrase(string user, string[] banner, string request)
        {
            int count = 0;
            InitializeComponent();
            this.Text = "Keyboard-Interactive Login for user " + user;
            label1.Text = request;
            foreach (string line in banner)
            {
                count += line.Trim().Length;
                listBox1.Items.Add(line);
            }
            if (count > 0) listBox1.Visible = true;
            textBox1.Focus();
        }
        internal PassPhrase(FileInfo keyFile)
        {
            InitializeComponent();
            label1.Text = $"Please enter the pass-phrase for keyfile '{keyFile.Name}'";
            textBox1.Focus();
        }
        internal PassPhrase(string userName)
        {
            InitializeComponent();
            this.Text = "Storing your password";
            label1.Text = $"Please enter the password for user '{userName}'";
            textBox1.Focus();
        }

        internal string Password { get { return textBox1.Text; } }

        private void btnOk_Click(object sender, EventArgs e)
        {
            Canceled = false;
            Hide();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            textBox1.Text = string.Empty;
            Hide();
        }

        private void textBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter) btnOk_Click(null, null);
        }
    }
}
